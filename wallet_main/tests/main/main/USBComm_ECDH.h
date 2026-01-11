#ifndef USB_COMM_ECDH_H
#define USB_COMM_ECDH_H

#include <Arduino.h>
#include <Adafruit_SSD1306.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

extern Adafruit_SSD1306 display;

#ifndef BTN_CONFIRM
#define BTN_CONFIRM 4
#endif
#ifndef BTN_DENY
#define BTN_DENY 23
#endif

static void oled(const String&a,const String&b="",const String&c=""){
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println(a);
  if(b.length()) display.println(b);
  if(c.length()) display.println(c);
  display.display();
}

static String toHex(const uint8_t*b,size_t n){
  static const char*H="0123456789ABCDEF";
  String s; s.reserve(n*2);
  for(size_t i=0;i<n;i++){ s+=H[b[i]>>4]; s+=H[b[i]&15]; }
  return s;
}

static int fromHex(const String&h,uint8_t*out,size_t max){
  auto v=[](char c)->int{
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return 10+(c-'a');
    if(c>='A'&&c<='F') return 10+(c-'A');
    return -1;
  };
  if(h.length()%2) return -1;
  size_t n=h.length()/2; if(n>max) return -1;
  for(size_t i=0;i<n;i++){
    int a=v(h[2*i]), b=v(h[2*i+1]);
    if(a<0||b<0) return -1;
    out[i] = (uint8_t)((a<<4)|b);
  }
  return (int)n;
}

static void sha256_bytes(const uint8_t*in,size_t n,uint8_t out[32]){
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c,0);
  mbedtls_sha256_update(&c,in,n);
  mbedtls_sha256_finish(&c,out);
  mbedtls_sha256_free(&c);
}

static void hkdf_sha256(const uint8_t*sec,size_t slen,
                        const uint8_t*salt,size_t slen2,
                        const uint8_t*info,size_t ilen,
                        uint8_t out[32]){
  auto hmac=[&](const uint8_t*k,size_t kl,
                const uint8_t*m,size_t ml,uint8_t o[32]){
    const size_t B=64; uint8_t kop[B]={0}, kip[B]={0}, tmp[B+ml]; uint8_t kh[32];
    if(kl>B){ sha256_bytes(k,kl,kh); k=kh; kl=32; }
    memcpy(kop,k,kl); memcpy(kip,k,kl);
    for(size_t i=0;i<B;i++){ kop[i]^=0x5c; kip[i]^=0x36; }
    memcpy(tmp,kip,B); memcpy(tmp+B,m,ml); sha256_bytes(tmp,B+ml,o);
    memcpy(tmp,kop,B); memcpy(tmp+B,o,32); sha256_bytes(tmp,B+32,o);
  };
  uint8_t prk[32]; hmac(salt,slen2,sec,slen,prk);
  uint8_t ib[64]; memcpy(ib,info,ilen); ib[ilen]=0x01;
  hmac(prk,32,ib,ilen+1,out);
}

static void aes_ctr_crypt(const uint8_t key[32],const uint8_t iv[16],
                          const uint8_t*in,uint8_t*out,size_t n){
  mbedtls_aes_context a; mbedtls_aes_init(&a);
  mbedtls_aes_setkey_enc(&a,key,256);
  unsigned char nc[16]; unsigned char sb[16]; size_t off=0;
  memcpy(nc,iv,16); memset(sb,0,sizeof(sb));
  mbedtls_aes_crypt_ctr(&a,n,&off,nc,sb,in,out);
  mbedtls_aes_free(&a);
}

static bool serialLine(String&out,uint32_t t=15000){
  out=""; uint32_t s=millis();
  while(millis()-s<t){
    while(Serial.available()){
      char c=(char)Serial.read();
      if(c=='\n'){ out.trim(); return true; }
      out+=c;
    }
    delay(2);
  }
  return false;
}

static String jfield(const String&s,const char*k){
  String q="\""+String(k)+"\"";
  int p=s.indexOf(q); if(p<0) return "";
  int c=s.indexOf(":",p);
  int q1=s.indexOf("\"",c);
  int q2=s.indexOf("\"",q1+1);
  if(c<0||q1<0||q2<0) return "";
  return s.substring(q1+1,q2);
}

struct USBSession {
  bool ok;
  uint8_t aesKey[32];
};

USBSession returnFalse(){
  USBSession sess;
  sess.ok = false;
  return sess;
}

// ---------- main ----------
USBSession runUSBECDH(Adafruit_SSD1306 &disp){
  pinMode(BTN_CONFIRM,INPUT_PULLUP);
  pinMode(BTN_DENY,INPUT_PULLUP);
  oled("USB mode","Waiting...");
  Serial.setTimeout(10);

  // Handshake: advertise readiness once per second UNTIL the host writes something.
  // DO NOT drain/flush after we detect host, to avoid discarding the JSON.
  unsigned long last=0;
  while(!Serial.available()){
    if(millis()-last>1000){ Serial.println("USB_READY"); last=millis(); }
    delay(10);
  }
  // <- At this point, the first bytes from PC may ALREADY be in the RX buffer.
  //     We must not read & discard them. Proceed directly.

  // RNG + ECDH setup
  mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg; mbedtls_ecdh_context ctx;
  mbedtls_entropy_init(&ent);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ecdh_init(&ctx);

  const char *pers="esp32_pairing";
  int rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                 (const unsigned char*)pers, strlen(pers));
  if(rc!=0){
    Serial.printf("{\"status\":\"error\",\"reason\":\"drbg_seed\",\"code\":%d}\n",rc);
    oled("Seed fail"); return returnFalse();
  }

  rc = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
  if(rc!=0){
    Serial.printf("{\"status\":\"error\",\"reason\":\"ecdh_setup\",\"code\":%d}\n",rc);
    oled("Setup fail"); return returnFalse();
  }

  // Make public in TLS ECPoint format: [len=65][0x04||X||Y]
  uint8_t my_pub_tls[200]; size_t my_pub_tls_len = 0;
  rc = mbedtls_ecdh_make_public(&ctx,
                                &my_pub_tls_len,
                                my_pub_tls,
                                sizeof(my_pub_tls),
                                mbedtls_ctr_drbg_random,
                                &drbg);
  if(rc!=0){
    Serial.printf("{\"status\":\"error\",\"reason\":\"make_public\",\"code\":%d}\n",rc);
    oled("Pub fail"); return returnFalse();
  }
  if(my_pub_tls_len < 2 || my_pub_tls[0] != 65 || my_pub_tls[1] != 0x04){
    Serial.println("{\"status\":\"error\",\"reason\":\"pub_format\"}");
    oled("Pub fmt"); return returnFalse();
  }
  uint8_t my_pub_raw[65];
  memcpy(my_pub_raw, &my_pub_tls[1], 65);

  // Read PC public (raw 65-byte hex)
  String ln;
  if(!serialLine(ln, 15000)){
    Serial.println("{\"status\":\"error\",\"reason\":\"timeout_pc_pub\"}");
    oled("No PC pub"); return returnFalse();
  }
  String pc_hex = jfield(ln,"pub"); if(pc_hex=="") pc_hex = jfield(ln,"pc_pub");
  uint8_t pc_pub_raw[65];
  if(fromHex(pc_hex, pc_pub_raw, sizeof(pc_pub_raw)) != 65 || pc_pub_raw[0] != 0x04){
    Serial.println("{\"status\":\"error\",\"reason\":\"pc_pub_hex\"}");
    oled("PC bad"); return returnFalse();
  }
  // Wrap to TLS ECPoint for mbedtls_ecdh_read_public
  uint8_t pc_pub_tls[66]; pc_pub_tls[0]=65; memcpy(pc_pub_tls+1, pc_pub_raw, 65);

  rc = mbedtls_ecdh_read_public(&ctx, pc_pub_tls, sizeof(pc_pub_tls));
  if(rc!=0){
    Serial.printf("{\"status\":\"error\",\"reason\":\"read_public\",\"code\":%d}\n",rc);
    oled("Read fail"); return returnFalse();
  }

  // Shared secret
  uint8_t shared[32]; size_t slen=0;
  rc = mbedtls_ecdh_calc_secret(&ctx, &slen, shared, sizeof(shared),
                                mbedtls_ctr_drbg_random, &drbg);
  if(rc!=0 || slen!=32){
    Serial.printf("{\"status\":\"error\",\"reason\":\"secret\",\"code\":%d}\n",rc);
    oled("Secret fail"); return returnFalse();
  }

  // Pair code = SHA256(shared || my_pub_raw || pc_pub_raw) % 1e6
  uint8_t mix[32+65+65];
  memcpy(mix, shared, 32);
  memcpy(mix+32, my_pub_raw, 65);
  memcpy(mix+97, pc_pub_raw, 65);
  uint8_t h[32]; sha256_bytes(mix, sizeof(mix), h);
  uint32_t code = ((uint32_t)h[0]<<24)|((uint32_t)h[1]<<16)|((uint32_t)h[2]<<8)|h[3];
  code %= 1000000;
  char codeStr[8]; snprintf(codeStr, sizeof(codeStr), "%06u", code);

  oled("PAIR CODE", codeStr, "OK=Allow");
  Serial.printf("{\"status\":\"ok\",\"wallet_pub\":\"%s\",\"code\":\"%s\"}\n",
                toHex(my_pub_raw,65).c_str(), codeStr);

  // User decision
  unsigned long t0=millis();
  while(true){
    if(digitalRead(BTN_CONFIRM)==LOW){
      Serial.println("{\"action\":\"user\",\"decision\":\"allow\"}");
      break;
    }
    if(digitalRead(BTN_DENY)==LOW){
      Serial.println("{\"action\":\"user\",\"decision\":\"deny\"}");
      oled("Denied"); return returnFalse();
    }
    if(millis()-t0>60000){
      Serial.println("{\"action\":\"user\",\"decision\":\"timeout\"}");
      oled("Timeout"); return returnFalse();
    }
    delay(10);
  }

  // Derive AES-256
  const uint8_t salt[] = {'U','S','B','P','A','I','R','v','1'};
  const uint8_t info[] = {'A','E','S','-','2','5','6','-','C','T','R'};
  uint8_t aesKey[32];
  hkdf_sha256(shared, 32, salt, sizeof(salt), info, sizeof(info), aesKey);
  oled("Paired OK","Securing...");
  delay(200);

  // Encrypted echo
  String msg;
  if(!serialLine(msg,12000)){
    Serial.println("{\"status\":\"error\",\"reason\":\"no_enc_msg\"}");
    return returnFalse();
  }
  String ivHex = jfield(msg,"iv");
  String plain = jfield(msg,"plain");
  if(ivHex.length()!=32 || plain==""){
    Serial.println("{\"status\":\"error\",\"reason\":\"enc_fields\"}");
    return returnFalse();
  }
  uint8_t iv[16];
  if(fromHex(ivHex, iv, 16) != 16){
    Serial.println("{\"status\":\"error\",\"reason\":\"iv_hex\"}");
    return returnFalse();
  }
  std::string in(plain.c_str());
  std::string out(in.size(), '\0');
  aes_ctr_crypt(aesKey, iv,
                (const uint8_t*)in.data(),
                (uint8_t*)out.data(),
                out.size());
  Serial.printf("{\"status\":\"ok\",\"echo\":\"%s\"}\n",
                toHex((const uint8_t*)out.data(), out.size()).c_str());
  oled("USB Enc OK");

  mbedtls_ecdh_free(&ctx);
  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&ent);
  USBSession sess;
  sess.ok = true;
  memcpy(sess.aesKey, aesKey, 32); // your computed AES key
  return sess;
}

#endif
