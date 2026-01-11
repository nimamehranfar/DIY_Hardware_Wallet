/**
 * QR Code generator library - Compact version for ESP32
 * Locked to Version 3 (29x29 modules) for OLED display
 * 
 * Copyright (c) 2017 Richard Moore (https://github.com/ricmoo/QRCode)
 * MIT License
 */

#include "qrcode.h"
#include <string.h>
#include <stdlib.h>

// Version 3 specific constants (29x29 modules)
static const int16_t NUM_ERROR_CORRECTION_CODEWORDS[4] = { 26, 15, 44, 36 };
static const int8_t NUM_ERROR_CORRECTION_BLOCKS[4] = { 1, 1, 2, 2 };
static const uint16_t NUM_RAW_DATA_MODULES = 567;

static int max(int a, int b) { return (a > b) ? a : b; }

static int8_t getAlphanumeric(char c) {
    if (c >= '0' && c <= '9') return (c - '0');
    if (c >= 'A' && c <= 'Z') return (c - 'A' + 10);
    switch (c) {
        case ' ': return 36; case '$': return 37; case '%': return 38;
        case '*': return 39; case '+': return 40; case '-': return 41;
        case '.': return 42; case '/': return 43; case ':': return 44;
    }
    return -1;
}

static bool isAlphanumeric(const char *text, uint16_t length) {
    while (length != 0) if (getAlphanumeric(text[--length]) == -1) return false;
    return true;
}

static bool isNumeric(const char *text, uint16_t length) {
    while (length != 0) { char c = text[--length]; if (c < '0' || c > '9') return false; }
    return true;
}

static char getModeBits(uint8_t version, uint8_t mode) {
    unsigned int modeInfo = 0x7bbb80a;
    char result = 8 + ((modeInfo >> (3 * mode)) & 0x07);
    if (result == 15) result = 16;
    return result;
}

typedef struct { uint32_t bitOffsetOrWidth; uint16_t capacityBytes; uint8_t *data; } BitBucket;

static uint16_t bb_getGridSizeBytes(uint8_t size) { return (((size * size) + 7) / 8); }
static uint16_t bb_getBufferSizeBytes(uint32_t bits) { return ((bits + 7) / 8); }

static void bb_initBuffer(BitBucket *bitBuffer, uint8_t *data, int32_t capacityBytes) {
    bitBuffer->bitOffsetOrWidth = 0;
    bitBuffer->capacityBytes = capacityBytes;
    bitBuffer->data = data;
    memset(data, 0, capacityBytes);
}

static void bb_initGrid(BitBucket *bitGrid, uint8_t *data, uint8_t size) {
    bitGrid->bitOffsetOrWidth = size;
    bitGrid->capacityBytes = bb_getGridSizeBytes(size);
    bitGrid->data = data;
    memset(data, 0, bitGrid->capacityBytes);
}

static void bb_appendBits(BitBucket *bitBuffer, uint32_t val, uint8_t length) {
    uint32_t offset = bitBuffer->bitOffsetOrWidth;
    for (int8_t i = length - 1; i >= 0; i--, offset++) {
        bitBuffer->data[offset >> 3] |= ((val >> i) & 1) << (7 - (offset & 7));
    }
    bitBuffer->bitOffsetOrWidth = offset;
}

static void bb_setBit(BitBucket *bitGrid, uint8_t x, uint8_t y, bool on) {
    uint32_t offset = y * bitGrid->bitOffsetOrWidth + x;
    uint8_t mask = 1 << (7 - (offset & 0x07));
    if (on) bitGrid->data[offset >> 3] |= mask;
    else bitGrid->data[offset >> 3] &= ~mask;
}

static void bb_invertBit(BitBucket *bitGrid, uint8_t x, uint8_t y, bool invert) {
    uint32_t offset = y * bitGrid->bitOffsetOrWidth + x;
    uint8_t mask = 1 << (7 - (offset & 0x07));
    bool on = ((bitGrid->data[offset >> 3] & (1 << (7 - (offset & 0x07)))) != 0);
    if (on ^ invert) bitGrid->data[offset >> 3] |= mask;
    else bitGrid->data[offset >> 3] &= ~mask;
}

static bool bb_getBit(BitBucket *bitGrid, uint8_t x, uint8_t y) {
    uint32_t offset = y * bitGrid->bitOffsetOrWidth + x;
    return (bitGrid->data[offset >> 3] & (1 << (7 - (offset & 0x07)))) != 0;
}

static void applyMask(BitBucket *modules, BitBucket *isFunction, uint8_t mask) {
    uint8_t size = modules->bitOffsetOrWidth;
    for (uint8_t y = 0; y < size; y++) {
        for (uint8_t x = 0; x < size; x++) {
            if (bb_getBit(isFunction, x, y)) continue;
            bool invert = 0;
            switch (mask) {
                case 0: invert = (x + y) % 2 == 0; break;
                case 1: invert = y % 2 == 0; break;
                case 2: invert = x % 3 == 0; break;
                case 3: invert = (x + y) % 3 == 0; break;
                case 4: invert = (x / 3 + y / 2) % 2 == 0; break;
                case 5: invert = x * y % 2 + x * y % 3 == 0; break;
                case 6: invert = (x * y % 2 + x * y % 3) % 2 == 0; break;
                case 7: invert = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
            }
            bb_invertBit(modules, x, y, invert);
        }
    }
}

static void setFunctionModule(BitBucket *modules, BitBucket *isFunction, uint8_t x, uint8_t y, bool on) {
    bb_setBit(modules, x, y, on);
    bb_setBit(isFunction, x, y, true);
}

static void drawFinderPattern(BitBucket *modules, BitBucket *isFunction, uint8_t x, uint8_t y) {
    uint8_t size = modules->bitOffsetOrWidth;
    for (int8_t i = -4; i <= 4; i++) {
        for (int8_t j = -4; j <= 4; j++) {
            uint8_t dist = max(abs(i), abs(j));
            int16_t xx = x + j, yy = y + i;
            if (0 <= xx && xx < size && 0 <= yy && yy < size)
                setFunctionModule(modules, isFunction, xx, yy, dist != 2 && dist != 4);
        }
    }
}

static void drawAlignmentPattern(BitBucket *modules, BitBucket *isFunction, uint8_t x, uint8_t y) {
    for (int8_t i = -2; i <= 2; i++)
        for (int8_t j = -2; j <= 2; j++)
            setFunctionModule(modules, isFunction, x + j, y + i, max(abs(i), abs(j)) != 1);
}

static void drawFormatBits(BitBucket *modules, BitBucket *isFunction, uint8_t ecc, uint8_t mask) {
    uint8_t size = modules->bitOffsetOrWidth;
    uint32_t data = ecc << 3 | mask;
    uint32_t rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    data = data << 10 | rem;
    data ^= 0x5412;
    
    for (uint8_t i = 0; i <= 5; i++) setFunctionModule(modules, isFunction, 8, i, ((data >> i) & 1) != 0);
    setFunctionModule(modules, isFunction, 8, 7, ((data >> 6) & 1) != 0);
    setFunctionModule(modules, isFunction, 8, 8, ((data >> 7) & 1) != 0);
    setFunctionModule(modules, isFunction, 7, 8, ((data >> 8) & 1) != 0);
    for (int8_t i = 9; i < 15; i++) setFunctionModule(modules, isFunction, 14 - i, 8, ((data >> i) & 1) != 0);
    for (int8_t i = 0; i <= 7; i++) setFunctionModule(modules, isFunction, size - 1 - i, 8, ((data >> i) & 1) != 0);
    for (int8_t i = 8; i < 15; i++) setFunctionModule(modules, isFunction, 8, size - 15 + i, ((data >> i) & 1) != 0);
    setFunctionModule(modules, isFunction, 8, size - 8, true);
}

static void drawFunctionPatterns(BitBucket *modules, BitBucket *isFunction, uint8_t version, uint8_t ecc) {
    uint8_t size = modules->bitOffsetOrWidth;
    for (uint8_t i = 0; i < size; i++) {
        setFunctionModule(modules, isFunction, 6, i, i % 2 == 0);
        setFunctionModule(modules, isFunction, i, 6, i % 2 == 0);
    }
    drawFinderPattern(modules, isFunction, 3, 3);
    drawFinderPattern(modules, isFunction, size - 4, 3);
    drawFinderPattern(modules, isFunction, 3, size - 4);
    if (version > 1) drawAlignmentPattern(modules, isFunction, 22, 22);
    drawFormatBits(modules, isFunction, ecc, 0);
}

static void drawCodewords(BitBucket *modules, BitBucket *isFunction, BitBucket *codewords) {
    uint32_t bitLength = codewords->bitOffsetOrWidth;
    uint8_t *data = codewords->data;
    uint8_t size = modules->bitOffsetOrWidth;
    uint32_t i = 0;
    
    for (int16_t right = size - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (uint8_t vert = 0; vert < size; vert++) {
            for (int j = 0; j < 2; j++) {
                uint8_t x = right - j;
                bool upwards = ((right & 2) == 0) ^ (x < 6);
                uint8_t y = upwards ? size - 1 - vert : vert;
                if (!bb_getBit(isFunction, x, y) && i < bitLength) {
                    bb_setBit(modules, x, y, ((data[i >> 3] >> (7 - (i & 7))) & 1) != 0);
                    i++;
                }
            }
        }
    }
}

#define PENALTY_N1  3
#define PENALTY_N2  3
#define PENALTY_N3  40
#define PENALTY_N4  10

static uint32_t getPenaltyScore(BitBucket *modules) {
    uint32_t result = 0;
    uint8_t size = modules->bitOffsetOrWidth;
    
    for (uint8_t y = 0; y < size; y++) {
        bool colorX = bb_getBit(modules, 0, y);
        for (uint8_t x = 1, runX = 1; x < size; x++) {
            bool cx = bb_getBit(modules, x, y);
            if (cx != colorX) { colorX = cx; runX = 1; }
            else { runX++; if (runX == 5) result += PENALTY_N1; else if (runX > 5) result++; }
        }
    }
    
    for (uint8_t x = 0; x < size; x++) {
        bool colorY = bb_getBit(modules, x, 0);
        for (uint8_t y = 1, runY = 1; y < size; y++) {
            bool cy = bb_getBit(modules, x, y);
            if (cy != colorY) { colorY = cy; runY = 1; }
            else { runY++; if (runY == 5) result += PENALTY_N1; else if (runY > 5) result++; }
        }
    }
    
    uint16_t black = 0;
    for (uint8_t y = 0; y < size; y++) {
        uint16_t bitsRow = 0, bitsCol = 0;
        for (uint8_t x = 0; x < size; x++) {
            bool color = bb_getBit(modules, x, y);
            if (x > 0 && y > 0) {
                bool colorUL = bb_getBit(modules, x - 1, y - 1);
                bool colorUR = bb_getBit(modules, x, y - 1);
                bool colorL = bb_getBit(modules, x - 1, y);
                if (color == colorUL && color == colorUR && color == colorL) result += PENALTY_N2;
            }
            bitsRow = ((bitsRow << 1) & 0x7FF) | color;
            bitsCol = ((bitsCol << 1) & 0x7FF) | bb_getBit(modules, y, x);
            if (x >= 10) {
                if (bitsRow == 0x05D || bitsRow == 0x5D0) result += PENALTY_N3;
                if (bitsCol == 0x05D || bitsCol == 0x5D0) result += PENALTY_N3;
            }
            if (color) black++;
        }
    }
    
    uint16_t total = size * size;
    for (uint16_t k = 0; black * 20 < (9 - k) * total || black * 20 > (11 + k) * total; k++) result += PENALTY_N4;
    return result;
}

static uint8_t rs_multiply(uint8_t x, uint8_t y) {
    uint16_t z = 0;
    for (int8_t i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * x;
    }
    return z;
}

static void rs_init(uint8_t degree, uint8_t *coeff) {
    memset(coeff, 0, degree);
    coeff[degree - 1] = 1;
    uint16_t root = 1;
    for (uint8_t i = 0; i < degree; i++) {
        for (uint8_t j = 0; j < degree; j++) {
            coeff[j] = rs_multiply(coeff[j], root);
            if (j + 1 < degree) coeff[j] ^= coeff[j + 1];
        }
        root = (root << 1) ^ ((root >> 7) * 0x11D);
    }
}

static void rs_getRemainder(uint8_t degree, uint8_t *coeff, uint8_t *data, uint8_t length, uint8_t *result, uint8_t stride) {
    for (uint8_t i = 0; i < length; i++) {
        uint8_t factor = data[i] ^ result[0];
        for (uint8_t j = 1; j < degree; j++) result[(j - 1) * stride] = result[j * stride];
        result[(degree - 1) * stride] = 0;
        for (uint8_t j = 0; j < degree; j++) result[j * stride] ^= rs_multiply(coeff[j], factor);
    }
}

static int8_t encodeDataCodewords(BitBucket *dataCodewords, const uint8_t *text, uint16_t length, uint8_t version) {
    int8_t mode = MODE_BYTE;
    
    if (isNumeric((char*)text, length)) {
        mode = MODE_NUMERIC;
        bb_appendBits(dataCodewords, 1 << MODE_NUMERIC, 4);
        bb_appendBits(dataCodewords, length, getModeBits(version, MODE_NUMERIC));
        uint16_t accumData = 0; uint8_t accumCount = 0;
        for (uint16_t i = 0; i < length; i++) {
            accumData = accumData * 10 + ((char)(text[i]) - '0');
            accumCount++;
            if (accumCount == 3) { bb_appendBits(dataCodewords, accumData, 10); accumData = 0; accumCount = 0; }
        }
        if (accumCount > 0) bb_appendBits(dataCodewords, accumData, accumCount * 3 + 1);
    } else if (isAlphanumeric((char*)text, length)) {
        mode = MODE_ALPHANUMERIC;
        bb_appendBits(dataCodewords, 1 << MODE_ALPHANUMERIC, 4);
        bb_appendBits(dataCodewords, length, getModeBits(version, MODE_ALPHANUMERIC));
        uint16_t accumData = 0; uint8_t accumCount = 0;
        for (uint16_t i = 0; i < length; i++) {
            accumData = accumData * 45 + getAlphanumeric((char)(text[i]));
            accumCount++;
            if (accumCount == 2) { bb_appendBits(dataCodewords, accumData, 11); accumData = 0; accumCount = 0; }
        }
        if (accumCount > 0) bb_appendBits(dataCodewords, accumData, 6);
    } else {
        bb_appendBits(dataCodewords, 1 << MODE_BYTE, 4);
        bb_appendBits(dataCodewords, length, getModeBits(version, MODE_BYTE));
        for (uint16_t i = 0; i < length; i++) bb_appendBits(dataCodewords, (char)(text[i]), 8);
    }
    return mode;
}

static void performErrorCorrection(uint8_t version, uint8_t ecc, BitBucket *data) {
    uint8_t numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecc];
    uint16_t totalEcc = NUM_ERROR_CORRECTION_CODEWORDS[ecc];
    uint16_t moduleCount = NUM_RAW_DATA_MODULES;
    uint8_t blockEccLen = totalEcc / numBlocks;
    uint8_t numShortBlocks = numBlocks - moduleCount / 8 % numBlocks;
    uint8_t shortBlockLen = moduleCount / 8 / numBlocks;
    uint8_t shortDataBlockLen = shortBlockLen - blockEccLen;
    
    uint8_t result[data->capacityBytes];
    memset(result, 0, sizeof(result));
    uint8_t coeff[blockEccLen];
    rs_init(blockEccLen, coeff);
    
    uint16_t offset = 0;
    uint8_t *dataBytes = data->data;
    
    for (uint8_t i = 0; i < shortDataBlockLen; i++) {
        uint16_t index = i;
        uint8_t stride = shortDataBlockLen;
        for (uint8_t blockNum = 0; blockNum < numBlocks; blockNum++) {
            result[offset++] = dataBytes[index];
            index += stride;
        }
    }
    
    uint8_t blockSize = shortDataBlockLen;
    for (uint8_t blockNum = 0; blockNum < numBlocks; blockNum++) {
        rs_getRemainder(blockEccLen, coeff, dataBytes, blockSize, &result[offset + blockNum], numBlocks);
        dataBytes += blockSize;
    }
    
    memcpy(data->data, result, data->capacityBytes);
    data->bitOffsetOrWidth = moduleCount;
}

static const uint8_t ECC_FORMAT_BITS = (0x02 << 6) | (0x03 << 4) | (0x00 << 2) | (0x01 << 0);

uint16_t qrcode_getBufferSize(uint8_t version) {
    return bb_getGridSizeBytes(4 * version + 17);
}

int8_t qrcode_initBytes(QRCode *qrcode, uint8_t *modules, uint8_t version, uint8_t ecc, uint8_t *data, uint16_t length) {
    version = 3; // Lock to version 3
    uint8_t size = version * 4 + 17;
    qrcode->version = version;
    qrcode->size = size;
    qrcode->ecc = ecc;
    qrcode->modules = modules;
    
    uint8_t eccFormatBits = (ECC_FORMAT_BITS >> (2 * ecc)) & 0x03;
    uint16_t moduleCount = NUM_RAW_DATA_MODULES;
    uint16_t dataCapacity = moduleCount / 8 - NUM_ERROR_CORRECTION_CODEWORDS[eccFormatBits];
    
    BitBucket codewords;
    uint8_t codewordBytes[bb_getBufferSizeBytes(moduleCount)];
    bb_initBuffer(&codewords, codewordBytes, (int32_t)sizeof(codewordBytes));
    
    int8_t mode = encodeDataCodewords(&codewords, data, length, version);
    if (mode < 0) return -1;
    qrcode->mode = mode;
    
    uint32_t padding = (dataCapacity * 8) - codewords.bitOffsetOrWidth;
    if (padding > 4) padding = 4;
    bb_appendBits(&codewords, 0, padding);
    bb_appendBits(&codewords, 0, (8 - codewords.bitOffsetOrWidth % 8) % 8);
    
    for (uint8_t padByte = 0xEC; codewords.bitOffsetOrWidth < (dataCapacity * 8); padByte ^= 0xEC ^ 0x11)
        bb_appendBits(&codewords, padByte, 8);
    
    BitBucket modulesGrid;
    bb_initGrid(&modulesGrid, modules, size);
    
    BitBucket isFunctionGrid;
    uint8_t isFunctionGridBytes[bb_getGridSizeBytes(size)];
    bb_initGrid(&isFunctionGrid, isFunctionGridBytes, size);
    
    drawFunctionPatterns(&modulesGrid, &isFunctionGrid, version, eccFormatBits);
    performErrorCorrection(version, eccFormatBits, &codewords);
    drawCodewords(&modulesGrid, &isFunctionGrid, &codewords);
    
    uint8_t mask = 0;
    int32_t minPenalty = 2147483647;
    for (uint8_t i = 0; i < 8; i++) {
        drawFormatBits(&modulesGrid, &isFunctionGrid, eccFormatBits, i);
        applyMask(&modulesGrid, &isFunctionGrid, i);
        int penalty = getPenaltyScore(&modulesGrid);
        if (penalty < minPenalty) { mask = i; minPenalty = penalty; }
        applyMask(&modulesGrid, &isFunctionGrid, i);
    }
    
    qrcode->mask = mask;
    drawFormatBits(&modulesGrid, &isFunctionGrid, eccFormatBits, mask);
    applyMask(&modulesGrid, &isFunctionGrid, mask);
    
    return 0;
}

int8_t qrcode_initText(QRCode *qrcode, uint8_t *modules, uint8_t version, uint8_t ecc, const char *data) {
    return qrcode_initBytes(qrcode, modules, version, ecc, (uint8_t*)data, strlen(data));
}

bool qrcode_getModule(QRCode *qrcode, uint8_t x, uint8_t y) {
    if (x >= qrcode->size || y >= qrcode->size) return false;
    uint32_t offset = y * qrcode->size + x;
    return (qrcode->modules[offset >> 3] & (1 << (7 - (offset & 0x07)))) != 0;
}
