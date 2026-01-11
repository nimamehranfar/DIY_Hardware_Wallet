// Buffer polyfill for React Native
import { Buffer } from 'buffer';
global.Buffer = Buffer;
import bs58 from 'bs58';

import { StatusBar } from 'expo-status-bar';
import { useState, useEffect, useRef } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
  Dimensions,
  RefreshControl,
  KeyboardAvoidingView,
  Platform,
  Keyboard,
  TouchableWithoutFeedback,
  Modal,
  Alert,
  Linking,
} from 'react-native';
import { LineChart } from 'react-native-chart-kit';
import * as Clipboard from 'expo-clipboard';
import { CameraView, Camera } from 'expo-camera';
import Svg, { Path, Circle, G, Rect } from 'react-native-svg';
import { useWalletStore } from './src/store/walletStore';
import { walletService } from './src/services/WalletService';
import { solanaService, setRpcUrl, getRpcUrl } from './src/services/SolanaService';
import { useSettingsStore, RPC_ENDPOINTS, CURRENCY_SYMBOLS, convertCurrency } from './src/store/settingsStore';

// Theme colors
const DARK_COLORS = {
  bg: '#0a0a12',
  card: '#16162a',
  primary: '#8b5cf6',
  secondary: '#c4a77d',
  success: '#22c55e',
  error: '#ef4444',
  text: '#ffffff',
  textMuted: '#9ca3af',
  border: '#2d2d4a',
  glass: 'rgba(40, 40, 70, 0.85)',
};

const LIGHT_COLORS = {
  bg: '#f5f5f7',
  card: '#ffffff',
  primary: '#8b5cf6',
  secondary: '#c4a77d',
  success: '#22c55e',
  error: '#ef4444',
  text: '#1a1a2e',
  textMuted: '#6b7280',
  border: '#e5e7eb',
  glass: 'rgba(255, 255, 255, 0.9)',
};

// Get current theme based on settings
const getColors = () => {
  const darkMode = useSettingsStore.getState().darkMode;
  return darkMode ? DARK_COLORS : LIGHT_COLORS;
};

// Default to dark for initial render
let COLORS = DARK_COLORS;

// ===== SVG ICONS =====
const EspressoLogo = ({ size = 48 }: { size?: number }) => (
  <Svg width={size} height={size} viewBox="0 0 512 512">
    {/* Steam ribbons - floating higher */}
    <Path
      d="M270 20c-30 35-18 60 12 88 28 26 32 48 8 72"
      stroke={COLORS.primary}
      strokeWidth="16"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
      opacity="0.5"
    />
    <Path
      d="M230 40c-24 30-14 50 10 74 22 22 26 40 6 60"
      stroke={COLORS.primary}
      strokeWidth="20"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
    {/* Cup body - connected path including rim */}
    <Path
      d="M160 210 L352 210 L352 290 C352 340 306 380 256 380 C206 380 160 340 160 290 Z"
      stroke={COLORS.primary}
      strokeWidth="20"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
    {/* Handle */}
    <Path
      d="M352 240 C400 240 420 260 420 290 C420 320 400 340 352 340"
      stroke={COLORS.primary}
      strokeWidth="20"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
    {/* Saucer - main curve */}
    <Path
      d="M120 410 Q256 470 392 410"
      stroke={COLORS.primary}
      strokeWidth="20"
      strokeLinecap="round"
      fill="none"
    />
    {/* Saucer shadow - parallel curve with proper spacing */}
    <Path
      d="M140 445 Q256 495 372 445"
      stroke={COLORS.primary}
      strokeWidth="14"
      strokeLinecap="round"
      fill="none"
      opacity="0.4"
    />
  </Svg>
);

const HomeIcon = ({ active }: { active: boolean }) => (
  <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
    <Path
      d="M3 9.5L12 3L21 9.5V20C21 20.5 20.5 21 20 21H15V14H9V21H4C3.5 21 3 20.5 3 20V9.5Z"
      stroke={active ? COLORS.primary : COLORS.textMuted}
      strokeWidth="2"
      fill={active ? COLORS.primary + '30' : 'none'}
    />
  </Svg>
);

const ChartIcon = ({ active }: { active: boolean }) => (
  <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
    <Path
      d="M3 3V21H21"
      stroke={active ? COLORS.primary : COLORS.textMuted}
      strokeWidth="2"
      strokeLinecap="round"
    />
    <Path
      d="M7 14L12 9L15 12L21 6"
      stroke={active ? COLORS.primary : COLORS.textMuted}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </Svg>
);

const UserIcon = ({ active }: { active: boolean }) => (
  <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
    <Circle
      cx="12" cy="8" r="4"
      stroke={active ? COLORS.primary : COLORS.textMuted}
      strokeWidth="2"
      fill={active ? COLORS.primary + '30' : 'none'}
    />
    <Path
      d="M4 20C4 16.5 7.5 14 12 14C16.5 14 20 16.5 20 20"
      stroke={active ? COLORS.primary : COLORS.textMuted}
      strokeWidth="2"
      strokeLinecap="round"
    />
  </Svg>
);

const SendIcon = () => (
  <Svg width={28} height={28} viewBox="0 0 24 24" fill="none">
    <Path d="M12 19V5M12 5L6 11M12 5L18 11" stroke={COLORS.text} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </Svg>
);

const ReceiveIcon = () => (
  <Svg width={28} height={28} viewBox="0 0 24 24" fill="none">
    <Path d="M12 5V19M12 19L6 13M12 19L18 13" stroke={COLORS.text} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </Svg>
);

const DropIcon = () => (
  <Svg width={28} height={28} viewBox="0 0 24 24" fill="none">
    <Path d="M12 2C12 2 6 10 6 14C6 17.3 8.7 20 12 20C15.3 20 18 17.3 18 14C18 10 12 2 12 2Z" stroke={COLORS.text} strokeWidth="2" fill={COLORS.primary + '40'} />
  </Svg>
);

const KeyIcon = () => (
  <Svg width={28} height={28} viewBox="0 0 24 24" fill="none">
    <Circle cx="8" cy="15" r="4" stroke={COLORS.text} strokeWidth="2" />
    <Path d="M11 12L20 3M18 3L20 3L20 5M15 8L17 6" stroke={COLORS.text} strokeWidth="2" strokeLinecap="round" />
  </Svg>
);

const SeedIcon = () => (
  <Svg width={28} height={28} viewBox="0 0 24 24" fill="none">
    <Path d="M12 3C12 3 8 6 8 10C8 12 9 14 12 15C15 14 16 12 16 10C16 6 12 3 12 3Z" fill={COLORS.primary + '40'} stroke={COLORS.text} strokeWidth="2" />
    <Path d="M12 15V21M12 21C10 21 8 19 8 17M12 21C14 21 16 19 16 17" stroke={COLORS.text} strokeWidth="2" strokeLinecap="round" />
  </Svg>
);

// ===== CONNECT SCREEN =====
function ConnectScreen() {
  const { deviceIP, connect, connecting, connectionError, loadSavedIP } = useWalletStore();
  const [ip, setIp] = useState(deviceIP || '');
  const [showScanner, setShowScanner] = useState(false);
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);
  const [scanned, setScanned] = useState(false);

  useEffect(() => {
    loadSavedIP().then((savedIp) => {
      if (savedIp) setIp(savedIp);
    });
  }, []);

  const openScanner = async () => {
    const { status } = await Camera.requestCameraPermissionsAsync();
    setHasPermission(status === 'granted');
    if (status === 'granted') {
      setScanned(false);
      setShowScanner(true);
    } else {
      Alert.alert('Camera Permission', 'Camera access is required to scan QR codes');
    }
  };

  const handleBarCodeScanned = ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);
    setShowScanner(false);

    // Parse IP:port from QR code
    const ipMatch = data.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$/);
    if (ipMatch) {
      setIp(ipMatch[1]);
      // Auto-connect after short delay
      setTimeout(() => handleConnect(), 300);
    } else {
      Alert.alert('Invalid QR', 'QR code does not contain a valid IP address');
    }
  };

  const handleConnect = async () => {
    Keyboard.dismiss();
    if (!ip.trim()) return;

    // Check if biometric is enabled and perform authentication
    const settings = useSettingsStore.getState();
    if (settings.biometricEnabled) {
      try {
        const LocalAuth = await import('expo-local-authentication');
        const hasHardware = await LocalAuth.hasHardwareAsync();
        const isEnrolled = await LocalAuth.isEnrolledAsync();

        if (hasHardware && isEnrolled) {
          const result = await LocalAuth.authenticateAsync({
            promptMessage: 'Authenticate to connect wallet',
            cancelLabel: 'Cancel',
            fallbackLabel: 'Enter Passcode',
            disableDeviceFallback: false,
          });

          if (!result.success) {
            return; // User cancelled or failed authentication
          }
        }
      } catch (e) {
        console.log('Biometric error:', e);
        // Continue to connect on error
      }
    }

    await connect(ip.trim());
  };

  return (
    <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
      <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView contentContainerStyle={styles.connectCard} keyboardShouldPersistTaps="handled">
          <EspressoLogo size={80} />
          <Text style={styles.title}>espresSol</Text>
          <Text style={styles.subtitle}>Hardware Wallet for Solana</Text>

          <View style={styles.inputContainer}>
            <Text style={styles.inputLabel}>Device IP Address</Text>
            <TextInput
              style={styles.input}
              value={ip}
              onChangeText={setIp}
              placeholder="192.168.1.100"
              placeholderTextColor={COLORS.textMuted}
              keyboardType="url"
              autoCapitalize="none"
              autoCorrect={false}
              returnKeyType="go"
              onSubmitEditing={handleConnect}
            />
            <TouchableOpacity
              style={[styles.button, { backgroundColor: '#333', marginTop: 8, paddingVertical: 12 }]}
              onPress={openScanner}
            >
              <Text style={[styles.buttonText, { fontSize: 14 }]}> Scan QR Code</Text>
            </TouchableOpacity>
          </View>

          <Text style={styles.hint}>Scan QR on ESP32 screen or enter IP manually</Text>

          {connectionError && (
            <View style={styles.errorBox}>
              <Text style={styles.errorText}>{connectionError}</Text>
            </View>
          )}

          <TouchableOpacity
            style={[styles.button, connecting && styles.buttonDisabled]}
            onPress={handleConnect}
            disabled={connecting}
          >
            {connecting ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Connect</Text>}
          </TouchableOpacity>

          {/* QR Scanner Modal */}
          <Modal visible={showScanner} animationType="slide">
            <View style={{ flex: 1, backgroundColor: '#000' }}>
              <CameraView
                style={{ flex: 1 }}
                facing="back"
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                onBarcodeScanned={scanned ? undefined : (result) => handleBarCodeScanned({ data: result.data })}
              />
              <View style={{ position: 'absolute', top: 50, left: 0, right: 0, alignItems: 'center' }}>
                <Text style={{ color: '#fff', fontSize: 18, fontWeight: '600' }}>Scan ESP32 QR Code</Text>
              </View>
              <TouchableOpacity
                style={{ position: 'absolute', bottom: 50, alignSelf: 'center', backgroundColor: COLORS.primary, paddingHorizontal: 24, paddingVertical: 12, borderRadius: 20 }}
                onPress={() => setShowScanner(false)}
              >
                <Text style={{ color: '#fff', fontSize: 16, fontWeight: '600' }}>Cancel</Text>
              </TouchableOpacity>
            </View>
          </Modal>
        </ScrollView>
        <StatusBar style="light" />
      </KeyboardAvoidingView>
    </TouchableWithoutFeedback>
  );
}

// ===== HOME TAB =====
function HomeTab({ setMessage }: { setMessage: (m: string) => void }) {
  const { publicKey, balance, balanceUSD, solPrice, refreshBalance } = useWalletStore();
  const [refreshing, setRefreshing] = useState(false);
  const [showSend, setShowSend] = useState(false);
  const [sendAddress, setSendAddress] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sending, setSending] = useState(false);
  const [airdropLoading, setAirdropLoading] = useState(false);
  const [recentAddresses, setRecentAddresses] = useState<string[]>([]);

  // Fetch recent addresses when send modal opens
  useEffect(() => {
    if (showSend && publicKey) {
      const fetchRecent = async () => {
        try {
          const txs = await solanaService.getTransactionHistory(publicKey, 20);
          // Get unique addresses we sent TO (not ourselves)
          const sentTo = txs
            .filter(tx => tx.type === 'send' && tx.otherParty !== publicKey)
            .map(tx => tx.otherParty)
            .filter((addr, idx, arr) => arr.indexOf(addr) === idx)
            .slice(0, 3);
          setRecentAddresses(sentTo);
        } catch (e) {
          console.log('[Send] Could not fetch recent addresses');
        }
      };
      fetchRecent();
    }
  }, [showSend, publicKey]);

  const onRefresh = async () => {
    setRefreshing(true);
    await refreshBalance();
    setRefreshing(false);
  };

  const copyAddress = async () => {
    if (!publicKey) return;
    await Clipboard.setStringAsync(publicKey);
    setMessage('Address copied!');
    setTimeout(() => setMessage(''), 3000);
  };

  const handleAirdrop = async () => {
    if (!publicKey) return;
    setAirdropLoading(true);
    setMessage('Requesting airdrop...');
    try {
      const response = await fetch('https://api.devnet.solana.com', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'requestAirdrop',
          params: [publicKey, 1000000000],
        }),
      });
      const data = await response.json();
      if (data.result) {
        setMessage('Airdrop sent! Refreshing in 10s...');
        setTimeout(async () => { await refreshBalance(); setMessage(''); }, 10000);
      } else {
        setMessage('Airdrop failed: ' + (data.error?.message || 'Unknown'));
      }
    } catch (e: any) {
      setMessage('Error: ' + e.message);
    }
    setAirdropLoading(false);
  };

  const handleShowMnemonic = async () => {
    setMessage('Check your device screen!');
    try {
      await walletService.showMnemonic();
      setTimeout(() => setMessage(''), 3000);
    } catch (e: any) {
      setMessage('Error: ' + e.message);
    }
  };

  const handleSend = async () => {
    if (!sendAddress || !sendAmount || !publicKey) {
      setMessage('Enter address and amount');
      return;
    }

    // Validate recipient address
    if (!solanaService.isValidAddress(sendAddress)) {
      setMessage('Invalid Solana address');
      return;
    }

    // Convert comma to dot for European number format support
    const normalizedAmount = sendAmount.replace(',', '.');
    const lamports = Math.floor(parseFloat(normalizedAmount) * 1e9);
    if (isNaN(lamports) || lamports <= 0) {
      setMessage('Invalid amount');
      return;
    }

    if (lamports > balance) {
      setMessage('Insufficient balance');
      return;
    }

    // Check if large amount confirmation is needed
    const settings = useSettingsStore.getState();
    const solAmount = lamports / 1e9;
    if (settings.largeAmountConfirmation && solAmount >= settings.largeAmountThreshold) {
      Alert.alert(
        'Large Transaction',
        `You are about to send ${solAmount.toFixed(4)} SOL. This is above your ${settings.largeAmountThreshold} SOL threshold.\n\nContinue?`,
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Continue', onPress: () => executeSend(lamports) }
        ]
      );
      return;
    }

    await executeSend(lamports);
  };

  const executeSend = async (lamports: number) => {
    if (!publicKey) return;

    setSending(true);
    setShowSend(false);
    setMessage('Building transaction...');

    try {
      // Prepare transfer message for ESP32 signing
      const { messageHex, blockhash, messageBytes } = await solanaService.prepareTransfer(
        publicKey,
        sendAddress,
        lamports
      );

      // Send to ESP32 for signing
      setMessage('Confirm on device...');
      console.log('[Send] Message hex length:', messageHex.length);

      const signatureB58 = await walletService.sign(messageHex);

      if (!signatureB58) {
        throw new Error('No signature returned');
      }

      console.log('[Send] Received signature:', signatureB58.slice(0, 20) + '...');

      // Convert signature from Base58 to hex for broadcast
      setMessage('Broadcasting to Solana...');
      const sigBytes = bs58.decode(signatureB58);
      const sigHex = Buffer.from(sigBytes).toString('hex');

      // Broadcast the signed transaction
      const txSignature = await solanaService.sendSignedTransaction(messageBytes, sigHex);

      console.log('[Send] Transaction broadcast! Sig:', txSignature);
      setMessage(`Success! TX: ${txSignature.slice(0, 12)}...`);
      setSendAddress('');
      setSendAmount('');

      // Refresh balance multiple times to catch confirmation
      setTimeout(async () => { await refreshBalance(); }, 2000);
      setTimeout(async () => { await refreshBalance(); }, 5000);
      setTimeout(async () => { await refreshBalance(); }, 10000);

      // Clear message after showing success
      setTimeout(() => {
        setMessage('');
      }, 8000);

    } catch (e: any) {
      console.error('[Send] Error:', e);
      if (e.message === 'rejected') {
        setMessage('Transaction rejected on device');
      } else if (e.message?.includes('timeout')) {
        setMessage('Signing timed out - try again');
      } else if (e.message?.includes('blockhash')) {
        setMessage('Transaction expired - try again');
      } else {
        setMessage('Error: ' + e.message);
      }
    }

    setSending(false);
  };

  const solBalance = balance / 1e9;

  // Get theme colors
  const settings = useSettingsStore();
  const colors = settings.darkMode ? DARK_COLORS : LIGHT_COLORS;

  // Apply showFullAddress setting to address display
  const displayAddress = publicKey
    ? (settings.showFullAddress ? publicKey : `${publicKey.slice(0, 6)}...${publicKey.slice(-4)}`)
    : '';

  return (
    <ScrollView
      style={[styles.tabContent, { backgroundColor: colors.bg }]}
      contentContainerStyle={styles.scrollContent}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.primary} />}
    >
      {/* Header */}
      <View style={styles.pageHeader}>
        <EspressoLogo size={32} />
        <Text style={[styles.pageTitle, { color: colors.text }]}>Home</Text>
      </View>

      {/* Balance Card */}
      <View style={[styles.balanceCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <Text style={[styles.balanceLabel, { color: colors.textMuted }]}>Total Balance</Text>
        <Text style={[styles.balanceValue, { color: colors.text }]}>
          {solBalance.toFixed(4)} <Text style={[styles.balanceCurrency, { color: colors.primary }]}>SOL</Text>
        </Text>
        <Text style={[styles.balanceUSD, { color: colors.success }]}>
          {CURRENCY_SYMBOLS[settings.currency]}{convertCurrency(balanceUSD, settings.currency).toFixed(2)} {settings.currency}
        </Text>
        <Text style={[styles.priceHint, { color: colors.textMuted }]}>1 SOL = {CURRENCY_SYMBOLS[settings.currency]}{convertCurrency(solPrice, settings.currency).toFixed(2)}</Text>
      </View>

      {/* Address */}
      <TouchableOpacity style={[styles.addressCard, { backgroundColor: colors.card, borderColor: colors.border }]} onPress={copyAddress}>
        <Text style={[styles.addressLabel, { color: colors.textMuted }]}>Tap to copy</Text>
        <Text style={[styles.addressShort, { color: colors.text }]} numberOfLines={settings.showFullAddress ? 2 : 1}>{displayAddress}</Text>
      </TouchableOpacity>

      {/* Quick Actions */}
      <View style={[styles.actionsCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <View style={styles.actionsRow}>
          <TouchableOpacity style={styles.actionBtn} onPress={() => setShowSend(true)}>
            <View style={[styles.actionIconWrap, { backgroundColor: colors.primary + '20', borderColor: colors.border }]}><SendIcon /></View>
            <Text style={[styles.actionLabel, { color: colors.text }]}>Send</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.actionBtn} onPress={copyAddress}>
            <View style={[styles.actionIconWrap, { backgroundColor: colors.success + '20', borderColor: colors.border }]}><ReceiveIcon /></View>
            <Text style={[styles.actionLabel, { color: colors.text }]}>Receive</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[styles.actionBtn, airdropLoading && styles.buttonDisabled]} onPress={handleAirdrop} disabled={airdropLoading}>
            <View style={[styles.actionIconWrap, { backgroundColor: colors.secondary + '20', borderColor: colors.border }]}><DropIcon /></View>
            <Text style={[styles.actionLabel, { color: colors.text }]}>Airdrop</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.actionBtn} onPress={handleShowMnemonic}>
            <View style={[styles.actionIconWrap, { backgroundColor: colors.error + '20', borderColor: colors.border }]}><SeedIcon /></View>
            <Text style={[styles.actionLabel, { color: colors.text }]}>Seed-Phrase</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Engraved Logo Watermark */}
      <View style={{ alignItems: 'center', marginTop: 40, marginBottom: 20, opacity: 0.15 }}>
        <EspressoLogo size={100} />
        <Text style={{ color: colors.primary, fontSize: 24, fontWeight: '700', marginTop: 8, letterSpacing: 2 }}>espresSol</Text>
      </View>

      {/* Send Modal */}
      <Modal visible={showSend} transparent animationType="fade">
        <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
          <View style={styles.modalOverlay}>
            <View style={[styles.modalContent, { backgroundColor: colors.card, borderColor: colors.border }]}>
              <Text style={[styles.modalTitle, { color: colors.text }]}>Send SOL</Text>

              {/* Recent Addresses Pills */}
              {recentAddresses.length > 0 && (
                <View style={styles.recentRow}>
                  <Text style={[styles.recentLabel, { color: colors.textMuted }]}>Recent:</Text>
                  {recentAddresses.map((addr) => (
                    <TouchableOpacity
                      key={addr}
                      style={[styles.recentPill, { backgroundColor: colors.border }]}
                      onPress={() => setSendAddress(addr)}
                    >
                      <Text style={[styles.recentPillText, { color: colors.text }]}>
                        {addr.slice(0, 4)}...{addr.slice(-4)}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              )}

              <TextInput style={[styles.input, { backgroundColor: colors.bg, borderColor: colors.border, color: colors.text }]} value={sendAddress} onChangeText={setSendAddress} placeholder="Recipient address" placeholderTextColor={colors.textMuted} autoCapitalize="none" />
              <TextInput style={[styles.input, { marginTop: 12, backgroundColor: colors.bg, borderColor: colors.border, color: colors.text }]} value={sendAmount} onChangeText={setSendAmount} placeholder="Amount (SOL)" placeholderTextColor={colors.textMuted} keyboardType="decimal-pad" />
              <Text style={[styles.hint, { color: colors.textMuted }]}>Balance: {solBalance.toFixed(4)} SOL</Text>
              <TouchableOpacity style={[styles.button, { marginTop: 16 }]} onPress={handleSend} disabled={sending}>
                {sending ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Send</Text>}
              </TouchableOpacity>
              <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 8, backgroundColor: colors.border }]} onPress={() => setShowSend(false)}>
                <Text style={[styles.buttonText, { color: colors.text }]}>Cancel</Text>
              </TouchableOpacity>
            </View>
          </View>
        </TouchableWithoutFeedback>
      </Modal>
    </ScrollView>
  );
}

function AnalyticsTab() {
  const { balance, balanceHistory, solPrice, balanceUSD, publicKey } = useWalletStore();
  const settings = useSettingsStore();
  const colors = settings.darkMode ? DARK_COLORS : LIGHT_COLORS;
  const solBalance = balance / 1e9;
  const [transactions, setTransactions] = useState<Array<{
    signature: string;
    type: 'send' | 'receive' | 'unknown';
    amount: number;
    otherParty: string;
    blockTime: number | null;
  }>>([]);
  const [loadingTx, setLoadingTx] = useState(false);
  const [selectedTx, setSelectedTx] = useState<{
    signature: string;
    type: 'send' | 'receive' | 'unknown';
    amount: number;
    otherParty: string;
    blockTime: number | null;
  } | null>(null);

  // Fetch real transactions from Solana
  useEffect(() => {
    if (!publicKey) return;

    const fetchTransactions = async () => {
      setLoadingTx(true);
      try {
        const txs = await solanaService.getTransactionHistory(publicKey, 10);
        setTransactions(txs);
      } catch (e) {
        console.error('[Analytics] Error fetching transactions:', e);
      }
      setLoadingTx(false);
    };

    fetchTransactions();

    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchTransactions, 30000);
    return () => clearInterval(interval);
  }, [publicKey]);

  // Prepare chart data - ensure at least 2 points and handle zero values
  const chartValues = balanceHistory.length > 0
    ? balanceHistory.map(h => Math.max(h.balance / 1e9, 0.0001))
    : [solBalance || 0.0001, solBalance || 0.0001];

  // Format labels to show only time (HH:MM)
  const chartLabels = balanceHistory.length > 0
    ? balanceHistory.map(h => {
      // Extract just the time part (assuming date format includes time)
      const parts = h.date.split(' ');
      if (parts.length > 1) {
        // Get time part and truncate to HH:MM
        const timePart = parts[parts.length - 1];
        const timeMatch = timePart.match(/(\d{1,2}:\d{2})/);
        return timeMatch ? timeMatch[1] : parts[0].slice(-5);
      }
      return h.date.slice(-5); // Last 5 chars as fallback
    })
    : ['Start', 'Now'];

  const chartData = {
    labels: chartLabels,
    datasets: [{ data: chartValues, strokeWidth: 2 }],
  };

  // Calculate chart width - min 80px per data point for good spacing
  const chartWidth = Math.max(
    Dimensions.get('window').width - 40,
    chartLabels.length * 80
  );

  // Format time ago
  const timeAgo = (timestamp: number | null) => {
    if (!timestamp) return 'Unknown';
    const seconds = Math.floor(Date.now() / 1000 - timestamp);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  return (
    <ScrollView style={[styles.tabContent, { backgroundColor: colors.bg }]} contentContainerStyle={styles.scrollContent}>
      {/* Header */}
      <View style={styles.pageHeader}>
        <ChartIcon active={true} />
        <Text style={[styles.pageTitle, { color: colors.text }]}>Analytics</Text>
      </View>

      <View style={styles.statsGrid}>
        <View style={[styles.statCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <Text style={[styles.statValue, { color: colors.text }]}>{solBalance.toFixed(4)}</Text>
          <Text style={[styles.statLabel, { color: colors.textMuted }]}>SOL Balance</Text>
        </View>
        <View style={[styles.statCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <Text style={[styles.statValue, { color: colors.text }]}>{CURRENCY_SYMBOLS[settings.currency]}{convertCurrency(balanceUSD, settings.currency).toFixed(2)}</Text>
          <Text style={[styles.statLabel, { color: colors.textMuted }]}>{settings.currency} Value</Text>
        </View>
        <View style={[styles.statCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <Text style={[styles.statValue, { color: colors.text }]}>{CURRENCY_SYMBOLS[settings.currency]}{convertCurrency(solPrice, settings.currency).toFixed(2)}</Text>
          <Text style={[styles.statLabel, { color: colors.textMuted }]}>SOL Price</Text>
        </View>
        <View style={[styles.statCard, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <Text style={[styles.statValue, { color: colors.text }]}>{transactions.length}</Text>
          <Text style={[styles.statLabel, { color: colors.textMuted }]}>Transactions</Text>
        </View>
      </View>

      <Text style={[styles.chartTitle, { color: colors.textMuted }]}>Balance History (SOL)</Text>
      <ScrollView horizontal showsHorizontalScrollIndicator={true} style={{ marginHorizontal: -10 }}>
        <LineChart
          data={chartData}
          width={chartWidth}
          height={180}
          yAxisSuffix=""
          yAxisLabel=""
          chartConfig={{
            backgroundColor: colors.card,
            backgroundGradientFrom: colors.card,
            backgroundGradientTo: colors.bg,
            decimalPlaces: 2,
            color: (opacity = 1) => `rgba(139, 92, 246, ${opacity})`,
            labelColor: () => colors.textMuted,
            propsForDots: { r: '5', strokeWidth: '2', stroke: colors.primary },
            propsForBackgroundLines: { strokeDasharray: '', stroke: colors.border },
            fillShadowGradientFrom: colors.primary,
            fillShadowGradientTo: 'transparent',
            fillShadowGradientOpacity: 0.3,
          }}
          bezier
          style={{ ...styles.chart, backgroundColor: colors.card, borderRadius: 16, marginHorizontal: 10 }}
          fromZero={true}
        />
      </ScrollView>

      {/* Transactions Section */}
      <Text style={[styles.chartTitle, { marginTop: 24, color: colors.textMuted }]}>Recent Transactions</Text>
      {loadingTx ? (
        <View style={styles.emptyState}>
          <ActivityIndicator color={colors.primary} />
        </View>
      ) : transactions.length === 0 ? (
        <View style={[styles.emptyState, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <Text style={[styles.emptyStateText, { color: colors.textMuted }]}>No transactions yet</Text>
        </View>
      ) : (
        transactions.map((tx) => (
          <TouchableOpacity key={tx.signature} style={[styles.txItem, { backgroundColor: colors.card, borderColor: colors.border }]} onPress={() => setSelectedTx(tx)}>
            <View style={[styles.txIcon, tx.type === 'receive' ? styles.txIconReceive : styles.txIconSend]}>
              <Text style={styles.txIconText}>{tx.type === 'receive' ? '↓' : '↑'}</Text>
            </View>
            <View style={styles.txDetails}>
              <Text style={[styles.txTitle, { color: colors.text }]}>
                {tx.type === 'receive'
                  ? `From ${tx.otherParty.slice(0, 6)}...`
                  : `To ${tx.otherParty.slice(0, 6)}...`}
              </Text>
              <Text style={[styles.txDate, { color: colors.textMuted }]}>{timeAgo(tx.blockTime)}</Text>
            </View>
            <Text style={[styles.txAmount, tx.type === 'receive' ? styles.txAmountReceive : styles.txAmountSend]}>
              {tx.type === 'receive' ? '+' : '-'}{(tx.amount / 1e9).toFixed(4)} SOL
            </Text>
          </TouchableOpacity>
        ))
      )}

      {/* Transaction Details Modal */}
      <Modal visible={!!selectedTx} transparent animationType="fade">
        <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.7)', justifyContent: 'center', padding: 20 }}>
          <View style={{ backgroundColor: colors.card, borderRadius: 20, padding: 20, borderWidth: 1, borderColor: colors.border }}>
            <Text style={{ fontSize: 20, fontWeight: '700', color: colors.text, marginBottom: 16, textAlign: 'center' }}>
              Transaction Details
            </Text>

            {selectedTx && (
              <>
                <View style={{ marginBottom: 12 }}>
                  <Text style={{ color: colors.textMuted, fontSize: 12, marginBottom: 4 }}>Type</Text>
                  <Text style={{ color: selectedTx.type === 'receive' ? '#22c55e' : '#ef4444', fontSize: 16, fontWeight: '600' }}>
                    {selectedTx.type === 'receive' ? '↓ Received' : '↑ Sent'}
                  </Text>
                </View>

                <View style={{ marginBottom: 12 }}>
                  <Text style={{ color: colors.textMuted, fontSize: 12, marginBottom: 4 }}>Amount</Text>
                  <Text style={{ color: colors.text, fontSize: 18, fontWeight: '700' }}>
                    {selectedTx.type === 'receive' ? '+' : '-'}{(selectedTx.amount / 1e9).toFixed(6)} SOL
                  </Text>
                </View>

                <View style={{ marginBottom: 12 }}>
                  <Text style={{ color: colors.textMuted, fontSize: 12, marginBottom: 4 }}>
                    {selectedTx.type === 'receive' ? 'From' : 'To'}
                  </Text>
                  <TouchableOpacity onPress={() => { Clipboard.setStringAsync(selectedTx.otherParty); Alert.alert('Copied', 'Address copied to clipboard'); }}>
                    <Text style={{ color: colors.primary, fontSize: 14 }} numberOfLines={2}>{selectedTx.otherParty}</Text>
                    <Text style={{ color: colors.textMuted, fontSize: 12 }}>Tap to copy</Text>
                  </TouchableOpacity>
                </View>

                <View style={{ marginBottom: 12 }}>
                  <Text style={{ color: colors.textMuted, fontSize: 12, marginBottom: 4 }}>Date</Text>
                  <Text style={{ color: colors.text, fontSize: 14 }}>
                    {selectedTx.blockTime ? new Date(selectedTx.blockTime * 1000).toLocaleString() : 'Unknown'}
                  </Text>
                </View>

                <View style={{ marginBottom: 16 }}>
                  <Text style={{ color: colors.textMuted, fontSize: 12, marginBottom: 4 }}>Signature</Text>
                  <TouchableOpacity onPress={() => {
                    Alert.alert(
                      'Transaction Signature',
                      selectedTx.signature,
                      [
                        { text: 'Copy', onPress: () => { Clipboard.setStringAsync(selectedTx.signature); } },
                        { text: 'View on Explorer', onPress: () => { Linking.openURL(`https://explorer.solana.com/tx/${selectedTx.signature}?cluster=devnet`); } },
                        { text: 'Cancel', style: 'cancel' }
                      ]
                    );
                  }}>
                    <Text style={{ color: colors.primary, fontSize: 12 }} numberOfLines={2}>{selectedTx.signature}</Text>
                    <Text style={{ color: colors.textMuted, fontSize: 12 }}>Tap for options</Text>
                  </TouchableOpacity>
                </View>
              </>
            )}

            <TouchableOpacity
              style={{ backgroundColor: colors.primary, paddingVertical: 12, borderRadius: 12 }}
              onPress={() => setSelectedTx(null)}
            >
              <Text style={{ color: '#fff', fontSize: 16, fontWeight: '600', textAlign: 'center' }}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
}

// ===== SETTINGS TAB =====
function SettingsTab({ setMessage }: { setMessage: (m: string) => void }) {
  const { publicKey, disconnect, deviceIP } = useWalletStore();
  const settings = useSettingsStore();

  const [showRecover, setShowRecover] = useState(false);
  const [showWifi, setShowWifi] = useState(false);
  const [showReset, setShowReset] = useState(false);
  const [showLicenses, setShowLicenses] = useState(false);
  const [words, setWords] = useState<string[]>(Array(12).fill(''));
  const [recovering, setRecovering] = useState(false);
  const [recoveryCodePending, setRecoveryCodePending] = useState(false);
  const [deviceCode, setDeviceCode] = useState('');
  const [wifiSSID, setWifiSSID] = useState('');
  const [wifiPassword, setWifiPassword] = useState('');
  const [sendingWifi, setSendingWifi] = useState(false);

  // Biometric check - simplified to avoid Metro bundling issues
  const checkBiometrics = async () => {
    try {
      // Just toggle the setting - actual biometric check would happen on app startup
      settings.setBiometricEnabled(!settings.biometricEnabled);
      if (!settings.biometricEnabled) {
        setMessage('Biometric unlock enabled! You\'ll be asked to authenticate on next launch.');
      } else {
        setMessage('Biometric unlock disabled');
      }
    } catch (e) {
      setMessage('Biometric settings updated');
    }
  };

  // Network change
  const handleNetworkChange = (network: 'devnet' | 'mainnet' | 'testnet') => {
    settings.setNetwork(network);
    setRpcUrl(RPC_ENDPOINTS[network]);
    setMessage(`Switched to ${network.toUpperCase()}`);
  };

  // Recovery - Step 1: Init recovery and show code on device
  const handleStartRecovery = async () => {
    const cleanWords = words.map(w => w.trim().toLowerCase());
    if (cleanWords.some(w => !w)) {
      setMessage('Please enter all 12 words');
      return;
    }

    setMessage('Requesting device code...');
    try {
      await walletService.initRecovery();
      setRecoveryCodePending(true);
      setMessage('Enter the 6-digit code shown on your device');
    } catch (e: any) {
      setMessage('Error: ' + e.message);
    }
  };

  // Recovery - Step 2: Submit with device code
  const handleRecovery = async () => {
    const cleanWords = words.map(w => w.trim().toLowerCase());
    const codeNum = parseInt(deviceCode, 10);

    if (isNaN(codeNum) || deviceCode.length !== 6) {
      setMessage('Please enter the 6-digit code from device');
      return;
    }

    setRecovering(true);
    setRecoveryCodePending(false);
    setShowRecover(false);
    setMessage('Recovering wallet...');

    try {
      const success = await walletService.recover(cleanWords, codeNum);
      if (success) {
        setMessage('Recovery successful! Device restarting...');
        setWords(Array(12).fill(''));
        setDeviceCode('');
        setTimeout(() => disconnect(), 3000);
      } else {
        setMessage('Recovery failed - check words or code');
      }
    } catch (e: any) {
      setMessage('Error: ' + e.message);
    }
    setRecovering(false);
  };

  // WiFi config
  const handleWifiConfig = async () => {
    if (!wifiSSID) {
      setMessage('Please enter WiFi SSID');
      return;
    }
    setSendingWifi(true);
    try {
      const success = await walletService.setWifi(wifiSSID, wifiPassword);
      if (success) {
        setMessage('WiFi configured! Device restarting...');
        setShowWifi(false);
        setTimeout(() => disconnect(), 3000);
      } else {
        setMessage('Failed to set WiFi');
      }
    } catch (e: any) {
      setMessage('Error: ' + e.message);
    }
    setSendingWifi(false);
  };

  // Factory reset
  const handleFactoryReset = async () => {
    setShowReset(false);
    setMessage('Confirm factory reset on device...');
    try {
      const success = await walletService.factoryReset();
      if (success) {
        setMessage('Factory reset complete! Device will restart.');
        // Disconnect since device is restarting
        setTimeout(() => {
          disconnect();
        }, 2000);
      } else {
        setMessage('Factory reset cancelled or failed');
      }
    } catch (e: any) {
      if (e.message?.includes('timeout')) {
        setMessage('Cancelled on device');
      } else {
        setMessage('Error: ' + e.message);
      }
    }
  };

  const updateWord = (index: number, value: string) => {
    const newWords = [...words];
    newWords[index] = value.toLowerCase().trim();
    setWords(newWords);
  };

  // Theme colors
  const colors = settings.darkMode ? DARK_COLORS : LIGHT_COLORS;

  return (
    <ScrollView style={[styles.tabContent, { backgroundColor: colors.bg }]} contentContainerStyle={styles.scrollContent}>
      {/* Header */}
      <View style={styles.pageHeader}>
        <UserIcon active={true} />
        <Text style={[styles.pageTitle, { color: colors.text }]}>Settings</Text>
      </View>

      {/* Wallet Info */}
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <View style={styles.profileHeader}>
          <EspressoLogo size={48} />
          <Text style={[styles.profileName, { color: colors.text }]}>espresSol</Text>
        </View>
        <View style={[styles.profileCard, { backgroundColor: colors.bg, borderColor: colors.border }]}>
          <Text style={[styles.profileLabel, { color: colors.textMuted }]}>Wallet Address</Text>
          <Text style={[styles.profileValue, { color: colors.text }]} numberOfLines={1}>
            {settings.showFullAddress ? publicKey : `${publicKey?.slice(0, 10)}...${publicKey?.slice(-8)}`}
          </Text>
        </View>
      </View>

      {/* Network & Connection */}
      <Text style={[styles.sectionTitle, { color: colors.textMuted }]}>Network & Connection</Text>
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <View style={styles.settingRow}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Network</Text>
          <View style={styles.networkPills}>
            <View style={[styles.networkPill, styles.networkPillActive]}>
              <Text style={[styles.networkPillText, styles.networkPillTextActive]}>Devnet</Text>
            </View>
            <TouchableOpacity
              style={[styles.networkPill, styles.networkPillDisabled]}
              onPress={() => setMessage('Mainnet coming soon!')}
            >
              <Text style={[styles.networkPillText, styles.networkPillTextDisabled]}>Mainnet</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.networkPill, styles.networkPillDisabled]}
              onPress={() => setMessage('Testnet coming soon!')}
            >
              <Text style={[styles.networkPillText, styles.networkPillTextDisabled]}>Testnet</Text>
            </TouchableOpacity>
          </View>
        </View>

        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Device IP</Text>
          <Text style={[styles.settingValue, { color: colors.textMuted }]}>{deviceIP || 'Not connected'}</Text>
        </View>
      </View>

      {/* Security */}
      <Text style={[styles.sectionTitle, { color: colors.textMuted }]}>Security</Text>
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <TouchableOpacity style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]} onPress={checkBiometrics}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Biometric Unlock</Text>
          <View style={[styles.toggle, settings.biometricEnabled && styles.toggleActive]}>
            <View style={[styles.toggleDot, settings.biometricEnabled && styles.toggleDotActive]} />
          </View>
        </TouchableOpacity>

        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Session Timeout: {settings.sessionTimeout}min</Text>
          <View style={styles.sliderRow}>
            <TouchableOpacity style={[styles.sliderBtn, { backgroundColor: colors.border }]} onPress={() => settings.setSessionTimeout(Math.max(1, settings.sessionTimeout - 1))}>
              <Text style={[styles.sliderBtnText, { color: colors.text }]}>−</Text>
            </TouchableOpacity>
            <View style={[styles.sliderTrack, { backgroundColor: colors.border }]}>
              <View style={[styles.sliderFill, { width: `${(settings.sessionTimeout / 30) * 100}%` }]} />
            </View>
            <TouchableOpacity style={[styles.sliderBtn, { backgroundColor: colors.border }]} onPress={() => settings.setSessionTimeout(Math.min(30, settings.sessionTimeout + 1))}>
              <Text style={[styles.sliderBtnText, { color: colors.text }]}>+</Text>
            </TouchableOpacity>
          </View>
        </View>

        <TouchableOpacity style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]} onPress={() => settings.setLargeAmountConfirmation(!settings.largeAmountConfirmation)}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Confirm large amounts</Text>
          <View style={[styles.toggle, settings.largeAmountConfirmation && styles.toggleActive]}>
            <View style={[styles.toggleDot, settings.largeAmountConfirmation && styles.toggleDotActive]} />
          </View>
        </TouchableOpacity>

        {settings.largeAmountConfirmation && (
          <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
            <Text style={[styles.settingLabel, { color: colors.text }]}>Threshold: {settings.largeAmountThreshold} SOL</Text>
            <View style={styles.sliderRow}>
              <TouchableOpacity style={[styles.sliderBtn, { backgroundColor: colors.border }]} onPress={() => settings.setLargeAmountThreshold(Math.max(0.1, settings.largeAmountThreshold - 0.5))}>
                <Text style={[styles.sliderBtnText, { color: colors.text }]}>−</Text>
              </TouchableOpacity>
              <View style={[styles.sliderTrack, { backgroundColor: colors.border }]}>
                <View style={[styles.sliderFill, { width: `${(settings.largeAmountThreshold / 10) * 100}%` }]} />
              </View>
              <TouchableOpacity style={[styles.sliderBtn, { backgroundColor: colors.border }]} onPress={() => settings.setLargeAmountThreshold(Math.min(10, settings.largeAmountThreshold + 0.5))}>
                <Text style={[styles.sliderBtnText, { color: colors.text }]}>+</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
      </View>

      {/* Display */}
      <Text style={[styles.sectionTitle, { color: colors.textMuted }]}>Display</Text>
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Currency</Text>
          <View style={styles.networkPills}>
            {(['USD', 'EUR', 'GBP'] as const).map((cur) => (
              <TouchableOpacity
                key={cur}
                style={[styles.networkPill, settings.currency === cur && styles.networkPillActive]}
                onPress={() => settings.setCurrency(cur)}
              >
                <Text style={[styles.networkPillText, settings.currency === cur && styles.networkPillTextActive]}>
                  {CURRENCY_SYMBOLS[cur]} {cur}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        <TouchableOpacity style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]} onPress={() => settings.setShowFullAddress(!settings.showFullAddress)}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Show full address</Text>
          <View style={[styles.toggle, settings.showFullAddress && styles.toggleActive]}>
            <View style={[styles.toggleDot, settings.showFullAddress && styles.toggleDotActive]} />
          </View>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]} onPress={() => settings.setDarkMode(!settings.darkMode)}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Dark Mode</Text>
          <View style={[styles.toggle, settings.darkMode && styles.toggleActive]}>
            <View style={[styles.toggleDot, settings.darkMode && styles.toggleDotActive]} />
          </View>
        </TouchableOpacity>
      </View>

      {/* Device Management */}
      <Text style={[styles.sectionTitle, { color: colors.textMuted }]}>Device Management</Text>
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <TouchableOpacity style={[styles.menuItem, { backgroundColor: colors.card, borderColor: colors.border }]} onPress={() => setShowWifi(true)}>
          <Svg width={20} height={20} viewBox="0 0 24 24" fill="none" style={{ marginRight: 14 }}>
            <Path d="M5 12.5C8.5 8 15.5 8 19 12.5" stroke={colors.text} strokeWidth="2" strokeLinecap="round" />
            <Path d="M8 15.5C10 13 14 13 16 15.5" stroke={colors.text} strokeWidth="2" strokeLinecap="round" />
            <Circle cx="12" cy="19" r="1" fill={colors.text} />
          </Svg>
          <Text style={[styles.menuText, { color: colors.text }]}>Configure WiFi</Text>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.menuItem, { backgroundColor: colors.card, borderColor: colors.border }]} onPress={async () => {
          setMessage('Check your device!');
          await walletService.showMnemonic();
        }}>
          <Svg width={20} height={20} viewBox="0 0 24 24" fill="none" style={{ marginRight: 14 }}>
            <Path d="M12 3C12 3 8 6 8 10C8 12 9 14 12 15C15 14 16 12 16 10C16 6 12 3 12 3Z" fill={colors.primary + '20'} stroke={colors.text} strokeWidth="2" />
            <Path d="M12 15V21M12 21C10 21 8 19 8 17M12 21C14 21 16 19 16 17" stroke={colors.text} strokeWidth="2" strokeLinecap="round" />
          </Svg>
          <Text style={[styles.menuText, { color: colors.text }]}>View Seed Phrase</Text>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.menuItem, { backgroundColor: colors.card, borderColor: colors.border }]} onPress={() => setShowRecover(true)}>
          <Svg width={20} height={20} viewBox="0 0 24 24" fill="none" style={{ marginRight: 14 }}>
            <Path d="M4 12C4 7.58 7.58 4 12 4C14.5 4 16.74 5.12 18.24 6.88" stroke={colors.text} strokeWidth="2" strokeLinecap="round" />
            <Path d="M20 12C20 16.42 16.42 20 12 20C9.5 20 7.26 18.88 5.76 17.12" stroke={colors.text} strokeWidth="2" strokeLinecap="round" />
            <Path d="M18 3V7H22" stroke={colors.text} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <Path d="M6 21V17H2" stroke={colors.text} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </Svg>
          <Text style={[styles.menuText, { color: colors.text }]}>Recover Wallet</Text>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.menuItem, styles.dangerItem, { backgroundColor: colors.card }]} onPress={() => setShowReset(true)}>
          <Svg width={20} height={20} viewBox="0 0 24 24" fill="none" style={{ marginRight: 14 }}>
            <Path d="M12 9V13M12 17H12.01" stroke={colors.error} strokeWidth="2" strokeLinecap="round" />
            <Path d="M5 19H19L12 5L5 19Z" stroke={colors.error} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </Svg>
          <Text style={[styles.menuText, { color: colors.error }]}>Factory Reset</Text>
        </TouchableOpacity>
      </View>

      {/* About */}
      <Text style={[styles.sectionTitle, { color: colors.textMuted }]}>About</Text>
      <View style={[styles.settingsSection, { backgroundColor: colors.card, borderColor: colors.border }]}>
        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>App Version</Text>
          <Text style={[styles.settingValue, { color: colors.textMuted }]}>1.0.0</Text>
        </View>
        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50' }]}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Firmware Version</Text>
          <Text style={[styles.settingValue, { color: colors.textMuted }]}>ESP32 v2.0</Text>
        </View>
        <View style={[styles.settingRow, { borderBottomColor: colors.border + '50', flexDirection: 'column', alignItems: 'flex-start' }]}>
          <Text style={[styles.settingLabel, { color: colors.text, marginBottom: 8 }]}>Developed by:</Text>
          <TouchableOpacity onPress={() => Linking.openURL('https://github.com/AEEltayeb')} style={{ marginBottom: 4 }}>
            <Text style={{ color: colors.primary, fontSize: 14 }}>👨‍💻@AEEltayeb</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => Linking.openURL('https://github.com/nimamehranfar')}>
            <Text style={{ color: colors.primary, fontSize: 14 }}>👨‍💻@nimamehranfar</Text>
          </TouchableOpacity>
        </View>
        <TouchableOpacity style={[styles.settingRow, { borderBottomWidth: 0 }]} onPress={() => setShowLicenses(true)}>
          <Text style={[styles.settingLabel, { color: colors.text }]}>Open Source Licenses</Text>
          <Text style={{ color: colors.textMuted, fontSize: 18 }}>›</Text>
        </TouchableOpacity>
      </View>

      {/* Disconnect */}
      <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 16, backgroundColor: colors.border }]} onPress={disconnect}>
        <Text style={[styles.buttonText, { color: colors.text }]}>Disconnect Wallet</Text>
      </TouchableOpacity>

      {/* Recovery Modal */}
      <Modal visible={showRecover} transparent animationType="slide">
        <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
          <View style={styles.modalOverlay}>
            <View style={[styles.modalContent, { maxHeight: '90%' }]}>
              <Text style={styles.modalTitle}>Recover Wallet</Text>
              <Text style={[styles.hint, { marginBottom: 16 }]}>
                {recoveryCodePending
                  ? '🔐 Enter the 6-digit code shown on your device:'
                  : 'Enter your 12-word backup phrase to restore wallet.'
                }
              </Text>

              {!recoveryCodePending ? (
                <>
                  <ScrollView style={{ maxHeight: 300 }}>
                    {words.map((word, index) => (
                      <View key={index} style={styles.wordInputRow}>
                        <Text style={styles.wordNumber}>{index + 1}.</Text>
                        <TextInput
                          style={[styles.input, styles.wordInput]}
                          value={word}
                          onChangeText={(val) => updateWord(index, val)}
                          placeholder={`Word ${index + 1}`}
                          placeholderTextColor={COLORS.textMuted}
                          autoCapitalize="none"
                          autoCorrect={false}
                        />
                      </View>
                    ))}
                  </ScrollView>

                  <TouchableOpacity style={[styles.button, { marginTop: 16 }]} onPress={handleStartRecovery} disabled={recovering}>
                    {recovering ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Get Device Code</Text>}
                  </TouchableOpacity>
                </>
              ) : (
                <>
                  <TextInput
                    style={[styles.input, { fontSize: 24, textAlign: 'center', letterSpacing: 4 }]}
                    value={deviceCode}
                    onChangeText={setDeviceCode}
                    placeholder="000000"
                    placeholderTextColor={COLORS.textMuted}
                    keyboardType="number-pad"
                    maxLength={6}
                  />

                  <TouchableOpacity style={[styles.button, { marginTop: 16 }]} onPress={handleRecovery} disabled={recovering}>
                    {recovering ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Recover Wallet</Text>}
                  </TouchableOpacity>

                  <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 8 }]} onPress={() => setRecoveryCodePending(false)}>
                    <Text style={styles.buttonText}>Back</Text>
                  </TouchableOpacity>
                </>
              )}

              <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 8 }]} onPress={() => { setShowRecover(false); setRecoveryCodePending(false); setDeviceCode(''); }}>
                <Text style={styles.buttonText}>Cancel</Text>
              </TouchableOpacity>
            </View>
          </View>
        </TouchableWithoutFeedback>
      </Modal>

      {/* WiFi Modal */}
      <Modal visible={showWifi} transparent animationType="fade">
        <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
          <View style={styles.modalOverlay}>
            <View style={styles.modalContent}>
              <Text style={styles.modalTitle}>Configure WiFi</Text>
              <TextInput
                style={styles.input}
                value={wifiSSID}
                onChangeText={setWifiSSID}
                placeholder="WiFi Network Name (SSID)"
                placeholderTextColor={COLORS.textMuted}
              />
              <TextInput
                style={[styles.input, { marginTop: 12 }]}
                value={wifiPassword}
                onChangeText={setWifiPassword}
                placeholder="Password"
                placeholderTextColor={COLORS.textMuted}
                secureTextEntry
              />
              <TouchableOpacity style={[styles.button, { marginTop: 16 }]} onPress={handleWifiConfig} disabled={sendingWifi}>
                {sendingWifi ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Save to Device</Text>}
              </TouchableOpacity>
              <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 8 }]} onPress={() => setShowWifi(false)}>
                <Text style={styles.buttonText}>Cancel</Text>
              </TouchableOpacity>
            </View>
          </View>
        </TouchableWithoutFeedback>
      </Modal>

      {/* Factory Reset Modal */}
      <Modal visible={showReset} transparent animationType="fade">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>⚠️ Factory Reset</Text>
            <Text style={[styles.hint, { color: COLORS.error, textAlign: 'center' }]}>
              This will ERASE all data on the device including your private keys!
            </Text>
            <Text style={[styles.hint, { marginTop: 16, textAlign: 'center' }]}>
              Make sure you have backed up your recovery phrase before proceeding.
            </Text>
            <TouchableOpacity style={[styles.button, { marginTop: 24, backgroundColor: COLORS.error }]} onPress={handleFactoryReset}>
              <Text style={styles.buttonText}>Yes, Erase Everything</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.button, styles.cancelButton, { marginTop: 8 }]} onPress={() => setShowReset(false)}>
              <Text style={styles.buttonText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>

      {/* Licenses Modal */}
      <Modal visible={showLicenses} transparent animationType="fade">
        <View style={styles.modalOverlay}>
          <View style={[styles.modalContent, { maxHeight: '80%' }]}>
            <Text style={styles.modalTitle}>Open Source Licenses</Text>
            <ScrollView style={{ maxHeight: 400 }}>
              <Text style={styles.licenseText}>
                This app uses the following open source libraries:{'\n\n'}
                • React Native (MIT){'\n'}
                • Expo (MIT){'\n'}
                • Zustand (MIT){'\n'}
                • react-native-chart-kit (MIT){'\n'}
                • bs58 (MIT){'\n'}
                • expo-local-authentication (MIT){'\n'}
                • expo-secure-store (MIT){'\n'}
                • AsyncStorage (MIT){'\n\n'}
                Hardware Firmware:{'\n'}
                • Arduino ESP32 (LGPL){'\n'}
                • mbedTLS (Apache 2.0){'\n'}
                • WebSockets (MIT)
              </Text>
            </ScrollView>
            <TouchableOpacity style={[styles.button, { marginTop: 16 }]} onPress={() => setShowLicenses(false)}>
              <Text style={styles.buttonText}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
}

// ===== MAIN DASHBOARD =====
function DashboardScreen() {
  const [activeTab, setActiveTab] = useState<'home' | 'analytics' | 'profile'>('home');
  const [message, setMessage] = useState('');
  const settings = useSettingsStore();
  const { disconnect } = useWalletStore();
  const colors = settings.darkMode ? DARK_COLORS : LIGHT_COLORS;
  const lastActivityRef = useRef(Date.now());

  // Session timeout - auto disconnect after inactivity
  useEffect(() => {
    const checkTimeout = setInterval(() => {
      const inactiveMs = Date.now() - lastActivityRef.current;
      const timeoutMs = settings.sessionTimeout * 60 * 1000; // Convert minutes to ms

      if (inactiveMs >= timeoutMs) {
        Alert.alert(
          'Session Timeout',
          'You have been disconnected due to inactivity.',
          [{ text: 'OK', onPress: () => disconnect() }]
        );
      }
    }, 30000); // Check every 30 seconds

    return () => clearInterval(checkTimeout);
  }, [settings.sessionTimeout, disconnect]);

  // Reset activity timer on any tap
  const handleUserActivity = () => {
    lastActivityRef.current = Date.now();
  };

  return (
    <View style={[styles.container, { backgroundColor: colors.bg }]} onTouchStart={handleUserActivity}>
      {message !== '' && (
        <TouchableOpacity style={[styles.messageBanner, { backgroundColor: colors.glass, borderColor: colors.border }]} onPress={() => setMessage('')} activeOpacity={0.8}>
          <Text style={[styles.messageText, { color: colors.text }]}>{message}</Text>
          <Text style={[styles.dismissHint, { color: colors.textMuted }]}>Tap to dismiss</Text>
        </TouchableOpacity>
      )}

      {activeTab === 'home' && <HomeTab setMessage={setMessage} />}
      {activeTab === 'analytics' && <AnalyticsTab />}
      {activeTab === 'profile' && <SettingsTab setMessage={setMessage} />}

      {/* Frosted Glass Navigation Bar */}
      <View style={styles.navContainer}>
        <View style={[styles.navBar, { backgroundColor: colors.glass, borderColor: settings.darkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)' }]}>
          <TouchableOpacity style={styles.navItem} onPress={() => setActiveTab('home')}>
            <HomeIcon active={activeTab === 'home'} />
            <Text style={[styles.navLabel, { color: activeTab === 'home' ? colors.primary : colors.textMuted }]}>Home</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.navItem} onPress={() => setActiveTab('analytics')}>
            <ChartIcon active={activeTab === 'analytics'} />
            <Text style={[styles.navLabel, { color: activeTab === 'analytics' ? colors.primary : colors.textMuted }]}>Analytics</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.navItem} onPress={() => setActiveTab('profile')}>
            <UserIcon active={activeTab === 'profile'} />
            <Text style={[styles.navLabel, { color: activeTab === 'profile' ? colors.primary : colors.textMuted }]}>Profile</Text>
          </TouchableOpacity>
        </View>
      </View>

      <StatusBar style={settings.darkMode ? "light" : "dark"} />
    </View>
  );
}

// ===== BIOMETRIC LOCK SCREEN =====
function BiometricLockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    checkBiometric();
  }, []);

  const checkBiometric = async () => {
    try {
      const LocalAuth = await import('expo-local-authentication');
      const hasHardware = await LocalAuth.hasHardwareAsync();
      const isEnrolled = await LocalAuth.isEnrolledAsync();

      if (!hasHardware || !isEnrolled) {
        // No biometrics available, just unlock
        onUnlock();
        return;
      }

      const result = await LocalAuth.authenticateAsync({
        promptMessage: 'Unlock espresSol Wallet',
        cancelLabel: 'Cancel',
        fallbackLabel: 'Enter Passcode',
        disableDeviceFallback: false,
        requireConfirmation: false,
      });

      if (result.success) {
        onUnlock();
      }
    } catch (e) {
      console.log('Biometric error:', e);
      // On error, allow unlock
      onUnlock();
    } finally {
      setChecking(false);
    }
  };

  // Get current theme
  const colors = useSettingsStore.getState().darkMode ? DARK_COLORS : LIGHT_COLORS;

  return (
    <View style={[styles.container, { backgroundColor: colors.bg, justifyContent: 'center', alignItems: 'center' }]}>
      <EspressoLogo size={100} />
      <Text style={[styles.title, { color: colors.text, marginTop: 24 }]}>espresSol</Text>
      <Text style={[styles.subtitle, { color: colors.textMuted }]}>
        {checking ? 'Authenticating...' : 'Tap to unlock'}
      </Text>
      {!checking && (
        <TouchableOpacity
          style={[styles.button, { marginTop: 32, width: 200 }]}
          onPress={checkBiometric}
        >
          <Text style={styles.buttonText}>Unlock</Text>
        </TouchableOpacity>
      )}
      {checking && <ActivityIndicator size="large" color={DARK_COLORS.primary} style={{ marginTop: 32 }} />}
    </View>
  );
}

// ===== MAIN APP =====
export default function App() {
  const { connected } = useWalletStore();
  const settings = useSettingsStore();
  const [, forceUpdate] = useState(0);

  // Update COLORS and force re-render when theme changes
  useEffect(() => {
    COLORS = settings.darkMode ? DARK_COLORS : LIGHT_COLORS;
    forceUpdate(n => n + 1); // Force re-render to apply new colors
  }, [settings.darkMode]);

  // Key forces full re-render when theme changes
  return (
    <View key={`theme-${settings.darkMode}`} style={{ flex: 1 }}>
      {connected ? <DashboardScreen /> : <ConnectScreen />}
    </View>
  );
}

// ===== STYLES =====
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: COLORS.bg },
  tabContent: { flex: 1 },
  scrollContent: { padding: 20, paddingTop: 60, paddingBottom: 120 },

  // Page Header
  pageHeader: { flexDirection: 'row', alignItems: 'center', marginBottom: 24 },
  pageTitle: { fontSize: 28, fontWeight: '700', color: COLORS.text, marginLeft: 12 },

  // Connect
  connectCard: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24, paddingTop: 80 },
  title: { fontSize: 32, fontWeight: '700', color: COLORS.text, marginTop: 16 },
  subtitle: { fontSize: 16, color: COLORS.textMuted, marginBottom: 40 },

  // Inputs
  inputContainer: { width: '100%', marginBottom: 12 },
  inputLabel: { color: COLORS.textMuted, marginBottom: 8, fontSize: 14 },
  input: { backgroundColor: COLORS.card, borderWidth: 1, borderColor: COLORS.border, borderRadius: 16, padding: 16, color: COLORS.text, fontSize: 16 },
  hint: { color: COLORS.textMuted, fontSize: 12, marginBottom: 16, textAlign: 'center' },

  // Buttons
  button: { backgroundColor: COLORS.primary, paddingVertical: 16, borderRadius: 16, width: '100%' },
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: COLORS.text, fontSize: 17, fontWeight: '600', textAlign: 'center' },
  cancelButton: { backgroundColor: COLORS.border },

  // Errors
  errorBox: { backgroundColor: COLORS.error + '20', borderColor: COLORS.error, borderWidth: 1, borderRadius: 12, padding: 12, marginBottom: 16, width: '100%' },
  errorText: { color: COLORS.error, textAlign: 'center' },

  // Message
  messageBanner: { backgroundColor: COLORS.glass, padding: 14, marginHorizontal: 20, marginTop: 50, borderRadius: 16, borderWidth: 1, borderColor: COLORS.border },
  messageText: { color: COLORS.text, textAlign: 'center', fontSize: 14 },
  dismissHint: { color: COLORS.textMuted, textAlign: 'center', fontSize: 10, marginTop: 4 },

  // Balance
  balanceCard: { backgroundColor: COLORS.card, borderRadius: 24, padding: 28, marginBottom: 16, borderWidth: 1, borderColor: COLORS.border },
  balanceLabel: { color: COLORS.textMuted, fontSize: 14, marginBottom: 8 },
  balanceValue: { color: COLORS.text, fontSize: 40, fontWeight: '700' },
  balanceCurrency: { fontSize: 22, color: COLORS.primary },
  balanceUSD: { color: COLORS.success, fontSize: 20, marginTop: 6 },
  priceHint: { color: COLORS.textMuted, fontSize: 12, marginTop: 8 },

  // Address
  addressCard: { backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 24, borderWidth: 1, borderColor: COLORS.border },
  addressLabel: { color: COLORS.textMuted, fontSize: 12, marginBottom: 4 },
  addressShort: { color: COLORS.primary, fontSize: 18, fontWeight: '600' },

  // Actions
  actionsCard: { backgroundColor: COLORS.card, borderRadius: 24, padding: 16, marginBottom: 24, borderWidth: 1, borderColor: COLORS.border },
  actionsRow: { flexDirection: 'row', justifyContent: 'space-between' },
  actionBtn: { alignItems: 'center', flex: 1 },
  actionIconWrap: { backgroundColor: COLORS.card, width: 56, height: 56, borderRadius: 28, justifyContent: 'center', alignItems: 'center', marginBottom: 8, borderWidth: 1, borderColor: COLORS.border },
  actionLabel: { color: COLORS.textMuted, fontSize: 12 },

  // Modal
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.85)', justifyContent: 'center', padding: 24 },
  modalContent: { backgroundColor: COLORS.card, borderRadius: 24, padding: 28, borderWidth: 1, borderColor: COLORS.border },
  modalTitle: { color: COLORS.text, fontSize: 24, fontWeight: '700', marginBottom: 24, textAlign: 'center' },

  // Recent Address Pills
  recentRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' },
  recentLabel: { color: COLORS.textMuted, fontSize: 12, marginRight: 8 },
  recentPill: { backgroundColor: COLORS.primary + '30', paddingHorizontal: 12, paddingVertical: 6, borderRadius: 16, marginRight: 8, marginBottom: 4, borderWidth: 1, borderColor: COLORS.primary + '50' },
  recentPillText: { color: COLORS.primary, fontSize: 12, fontWeight: '600' },

  // Analytics
  statsGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', marginBottom: 24 },
  statCard: { width: '48%', backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 12, alignItems: 'center', borderWidth: 1, borderColor: COLORS.border },
  statValue: { color: COLORS.text, fontSize: 22, fontWeight: '700' },
  statLabel: { color: COLORS.textMuted, fontSize: 12, marginTop: 4 },
  chartTitle: { color: COLORS.textMuted, fontSize: 14, marginBottom: 12 },
  chart: { borderRadius: 16 },

  // Profile
  profileHeader: { alignItems: 'center', marginBottom: 24 },
  profileName: { color: COLORS.text, fontSize: 24, fontWeight: '700', marginTop: 12 },
  profileCard: { backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 24, borderWidth: 1, borderColor: COLORS.border },
  profileLabel: { color: COLORS.textMuted, fontSize: 12, marginBottom: 4 },
  profileValue: { color: COLORS.text, fontSize: 11, fontFamily: 'monospace' },
  menuItem: { flexDirection: 'row', alignItems: 'center', backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 12, borderWidth: 1, borderColor: COLORS.border },
  menuIconText: { fontSize: 20, marginRight: 14 },
  menuText: { color: COLORS.text, fontSize: 16, marginLeft: 12 },
  dangerItem: { borderColor: COLORS.error + '50' },

  // Recovery Word Input
  wordInputRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 8 },
  wordNumber: { color: COLORS.textMuted, fontSize: 14, width: 30 },
  wordInput: { flex: 1, marginBottom: 0, padding: 12 },

  // Transactions
  txItem: { flexDirection: 'row', alignItems: 'center', backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 12, borderWidth: 1, borderColor: COLORS.border },
  txIcon: { width: 40, height: 40, borderRadius: 20, justifyContent: 'center', alignItems: 'center', marginRight: 12 },
  txIconReceive: { backgroundColor: COLORS.success + '30' },
  txIconSend: { backgroundColor: COLORS.error + '30' },
  txIconText: { fontSize: 18 },
  txDetails: { flex: 1 },
  txTitle: { color: COLORS.text, fontSize: 14, fontWeight: '600' },
  txDate: { color: COLORS.textMuted, fontSize: 12, marginTop: 2 },
  txAmount: { fontSize: 14, fontWeight: '700' },
  txAmountReceive: { color: COLORS.success },
  txAmountSend: { color: COLORS.error },
  emptyState: { alignItems: 'center', padding: 32 },
  emptyStateText: { color: COLORS.textMuted, fontSize: 14 },

  // Navigation Bar - Frosted Glass Pill
  navContainer: { position: 'absolute', bottom: 24, left: 24, right: 24 },
  navBar: {
    flexDirection: 'row',
    backgroundColor: COLORS.glass,
    borderRadius: 40,
    paddingVertical: 12,
    paddingHorizontal: 8,
    justifyContent: 'space-around',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.1)',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.4,
    shadowRadius: 16,
    elevation: 10,
  },
  navItem: { alignItems: 'center', paddingHorizontal: 24, paddingVertical: 6 },
  navLabel: { color: COLORS.textMuted, fontSize: 11, marginTop: 4, fontWeight: '500' },
  navLabelActive: { color: COLORS.primary },

  // Settings Page
  sectionTitle: { color: COLORS.textMuted, fontSize: 12, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 1, marginTop: 24, marginBottom: 12 },
  settingsSection: { backgroundColor: COLORS.card, borderRadius: 16, padding: 16, marginBottom: 8, borderWidth: 1, borderColor: COLORS.border },
  settingRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: COLORS.border + '50' },
  settingLabel: { color: COLORS.text, fontSize: 14, flex: 1 },
  settingValue: { color: COLORS.textMuted, fontSize: 14 },

  // Toggle Switch
  toggle: { width: 48, height: 28, borderRadius: 14, backgroundColor: COLORS.border, justifyContent: 'center', padding: 2 },
  toggleActive: { backgroundColor: COLORS.primary },
  toggleDot: { width: 24, height: 24, borderRadius: 12, backgroundColor: COLORS.text },
  toggleDotActive: { alignSelf: 'flex-end' },

  // Network Pills
  networkPills: { flexDirection: 'row' },
  networkPill: { paddingHorizontal: 12, paddingVertical: 6, borderRadius: 16, backgroundColor: COLORS.border, marginLeft: 8 },
  networkPillActive: { backgroundColor: COLORS.primary },
  networkPillDisabled: { backgroundColor: COLORS.border + '50', opacity: 0.5 },
  networkPillText: { color: COLORS.textMuted, fontSize: 12, fontWeight: '600' },
  networkPillTextActive: { color: COLORS.text },
  networkPillTextDisabled: { color: COLORS.textMuted + '80' },

  // Slider
  sliderRow: { flexDirection: 'row', alignItems: 'center', marginLeft: 8 },
  sliderBtn: { width: 32, height: 32, borderRadius: 16, backgroundColor: COLORS.border, justifyContent: 'center', alignItems: 'center' },
  sliderBtnText: { color: COLORS.text, fontSize: 18, fontWeight: '700' },
  sliderTrack: { width: 80, height: 4, backgroundColor: COLORS.border, borderRadius: 2, marginHorizontal: 8 },
  sliderFill: { height: 4, backgroundColor: COLORS.primary, borderRadius: 2 },

  // License Text
  licenseText: { color: COLORS.textMuted, fontSize: 12, lineHeight: 20 },
});
