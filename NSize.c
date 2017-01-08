#include "NSize.h"
#include <string.h>
#include <stdio.h>

#define MAXBLOCKSIZE 1073741824
#define MINBLOCKSIZE 8

//supplied key can be padded up to next keysize, or truncated to fit max keysize, so any keysize should be ok, handle during keygen
#define KEYSIZE128 16
#define KEYSIZE256 32
#define KEYSIZE512 64

#define MIXSTEP 2

#define ENC 0
#define DEC 1

#define VAR 0
#define FIN 1

int32_t MOD(int32_t a, int32_t b) {
    return (a % b) >= 0 ? (a % b) : (a % b) + b;
}

//Tables from AES

static const uint8_t AES_SBox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t AES_InvSBox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t AES_Rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

static const uint8_t A_Values[] = {
                1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61,65,
                69,73,77,81,85,89,93,97,101,105,109,113,117,121,
                125,129,133,137,141,145,149,153,157,161,165,169,
                173,177,181,185,189,193,197,201,205,209,213,217,
                221,225,229,233,237,241,245,249,253};
static const uint8_t C_Values[] = {
                1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,
                39,41,43,45,47,49,51,53,55,57,59,61,63,65,67,69,71,73,
                75,77,79,81,83,85,87,89,91,93,95,97,99,101,103,105,107,
                109,111,113,115,117,119,121,123,125,127,129,131,133,135,
                137,139,141,143,145,147,149,151,153,155,157,159,161,163,
                165,167,169,171,173,175,177,179,181,183,185,187,189,191,
                193,195,197,199,201,203,205,207,209,211,213,215,217,219,
                221,223,225,227,229,231,233,235,237,239,241,243,245,247,
                249,251,253,255};
                
static const uint32_t aSize = 64;
static const uint32_t cSize = 128;
static const uint32_t oSize = 256;

//Encryption/Decryption Variables

uint32_t permM, permA, permC, permN, permS, aderive, cderive;  //Message permutation variables, aderive and cderive will be calculated during var selection process
uint8_t DSBoxes[6][256]; //round dynamic sboxes, need only generate forward for encryption and reverse for decryption
uint8_t DSBoxVars[6][3]; //Vars to generate Dynamic SBoxes, [n][0] = aN, [n][1] = oN, [n][2] = cN
uint8_t KeySlide[68]; //Array to hold the steps necessary to generate the key for the final xor and the vars during setup, size = keysize max + 4 bytes
int8_t SlideIndex;
int8_t SlideModulus;
uint8_t ivalue;
uint8_t Keysize; //size of actual key
uint32_t messageSize; //size of the whole message

//AES Key Scheduling
void keyslideInit(uint8_t * key, uint32_t keysize) {
    memset(KeySlide, 0, 68);
    if (keysize <= KEYSIZE128) {
        Keysize = KEYSIZE128;
        memcpy(KeySlide, key, keysize);
        SlideIndex = Keysize;
        SlideModulus = Keysize + 4;
        ivalue = 1;
        return;
    }
    if (keysize <= KEYSIZE256) {
        Keysize = KEYSIZE256;
        memcpy(KeySlide, key, keysize);
        SlideIndex = Keysize;
        SlideModulus = Keysize + 4;
        ivalue = 1;
        return;
    }
    Keysize = KEYSIZE512;
    if (keysize > KEYSIZE512) {
        keysize =  KEYSIZE512;
    }
    SlideIndex = Keysize;
    SlideModulus = Keysize + 4;
    ivalue = 1;
    memcpy(KeySlide, key, keysize);
    return;
}

//Modified AES Key Schedule
uint32_t getNextExpandedKey(uint8_t flag) {
    uint8_t temp[4];
    
    if (flag == FIN) {
        temp[0] = AES_SBox[KeySlide[MOD(SlideIndex - 4, SlideModulus)]];
        temp[1] = AES_SBox[KeySlide[MOD(SlideIndex - 3, SlideModulus)]];
        temp[2] = AES_SBox[KeySlide[MOD(SlideIndex - 2, SlideModulus)]];
        temp[3] = AES_SBox[KeySlide[MOD(SlideIndex - 1, SlideModulus)]];
    } else {
        temp[0] = AES_InvSBox[KeySlide[MOD(SlideIndex - 4, SlideModulus)]];
        temp[1] = AES_InvSBox[KeySlide[MOD(SlideIndex - 3, SlideModulus)]];
        temp[2] = AES_InvSBox[KeySlide[MOD(SlideIndex - 2, SlideModulus)]];
        temp[3] = AES_InvSBox[KeySlide[MOD(SlideIndex - 1, SlideModulus)]];
    
    }
    
    ((uint32_t *)temp)[0] = (((uint32_t *)temp)[0] << 8) ^ (((uint32_t *)temp)[0] >> 24);
    temp[0] ^= AES_Rcon[ivalue];
    ++ivalue; 
    
    temp[0] ^= KeySlide[MOD(SlideIndex - Keysize, SlideModulus)];
    temp[1] ^= KeySlide[MOD(SlideIndex - Keysize + 1, SlideModulus)];
    temp[2] ^= KeySlide[MOD(SlideIndex - Keysize + 2, SlideModulus)];
    temp[3] ^= KeySlide[MOD(SlideIndex - Keysize + 3, SlideModulus)];
    
    KeySlide[MOD(SlideIndex, SlideModulus)] = temp[0];
    KeySlide[MOD(SlideIndex + 1, SlideModulus)] = temp[1];
    KeySlide[MOD(SlideIndex + 2, SlideModulus)] = temp[2];
    KeySlide[MOD(SlideIndex + 3, SlideModulus)] = temp[3];
    SlideIndex = (SlideIndex + 4) % SlideModulus;
    return ((uint32_t*)temp)[0];
}
//End AES Key Scheduling

//Permutation Code
//Get the right index
uint32_t permFunc(uint32_t x) {
    return (x * permA + permC) % permM;
}

//select perm variables
void choosePerm() {
    
    uint32_t diff;
    permM = 4;
    while (1 == 1) {
        if (2 * permM > messageSize) {
            break;
        }
        permM *= 2;
    }

    permA = (aderive % (permM / 4)) * 4 + 1;
    permC = (cderive % (permM / 2)) * 2 + 1;

    if (permM == messageSize) {
        permN = 1;
        permS = -1;
        return;
    }

    diff = permM - (messageSize - permM);
    if (diff > (permM / 3)) {
        permN = 2;
        permS = -1;
        return;
    }
    permN = 3;
    permS = messageSize / 2 - permM / 2;
    return;
}

//do permuation forward
void perm1(uint8_t* out, uint32_t zero) {
    uint32_t count = 0;
    uint32_t dest = zero;
    uint32_t hold1, hold2;
    hold1 = out[zero];
    for (count = 0; count < permM; ++count) {
        dest = permFunc(dest - zero) + zero;
        hold2 = out[dest];
        out[dest] = AES_SBox[hold1];
        hold1 = hold2;
    }
}

//permutation inverse
void perm1Inv(uint8_t* out, uint32_t zero) {

    uint32_t count = 0;
    uint32_t dest = zero, prev = zero;
    uint8_t keep;
    keep = out[zero];
    for (count = 0; count < permM - 1; ++count) {
        dest = permFunc(prev - zero) + zero;
        out[prev] = AES_InvSBox[out[dest]];
        prev = dest;
    }
    out[prev] = AES_InvSBox[keep];
}

void perm2(uint8_t* out) {
    perm1(out, 0);
    perm1(out, messageSize - permM);
}

void perm2Inv(uint8_t* out) {

    perm1Inv(out, messageSize - permM);
    perm1Inv(out, 0);
}

void perm3(uint8_t* out) {
    perm1(out, 0);
    perm1(out, permS);
    perm1(out, messageSize - permM);
}

void perm3Inv(uint8_t* out) {
    
    perm1Inv(out, messageSize - permM);
    perm1Inv(out, permS);
    perm1Inv(out, 0);
    
}

void perm(uint8_t* out) {
    switch(permN) {
        case 1:
            perm1(out, 0);
            break;
        case 2:
            perm2(out);
            break;
        case 3:
            perm3(out);
            break;
    }
}

void permInv(uint8_t* out) {
    switch(permN) {
        case 1:
            perm1Inv(out, 0);
            break;
        case 2:
            perm2Inv(out);
            break;
        case 3:
            perm3Inv(out);
            break;
    }
}
//end Permutation code
//SBox generation function
int sBoxBuilder(uint8_t mode) {
    uint32_t index = 0;
    switch(mode) {
        case ENC: //encryption
            
            for (index = 0; index < 256; index++) {
                DSBoxes[0][index] = AES_SBox[( DSBoxVars[0][0] * (index + DSBoxVars[0][1]) + DSBoxVars[0][2] ) % 256];
                DSBoxes[1][index] = AES_SBox[( DSBoxVars[1][0] * (index + DSBoxVars[1][1]) + DSBoxVars[1][2] ) % 256];
                DSBoxes[2][index] = AES_SBox[( DSBoxVars[2][0] * (index + DSBoxVars[2][1]) + DSBoxVars[2][2] ) % 256];
                DSBoxes[3][index] = AES_SBox[( DSBoxVars[3][0] * (index + DSBoxVars[3][1]) + DSBoxVars[3][2] ) % 256];
                DSBoxes[4][index] = AES_SBox[( DSBoxVars[4][0] * (index + DSBoxVars[4][1]) + DSBoxVars[4][2] ) % 256];
                DSBoxes[5][index] = AES_SBox[( DSBoxVars[5][0] * (index + DSBoxVars[5][1]) + DSBoxVars[5][2] ) % 256];

            }
            
            return 1;
            break;
        case DEC: //decryption
            for (index = 0; index < 256; ++index) {
                DSBoxes[0][AES_SBox[( DSBoxVars[0][0] * (index + DSBoxVars[0][1]) + DSBoxVars[0][2] ) % 256]] = index;
                DSBoxes[1][AES_SBox[( DSBoxVars[1][0] * (index + DSBoxVars[1][1]) + DSBoxVars[1][2] ) % 256]] = index;
                DSBoxes[2][AES_SBox[( DSBoxVars[2][0] * (index + DSBoxVars[2][1]) + DSBoxVars[2][2] ) % 256]] = index;
                DSBoxes[3][AES_SBox[( DSBoxVars[3][0] * (index + DSBoxVars[3][1]) + DSBoxVars[3][2] ) % 256]] = index;
                DSBoxes[4][AES_SBox[( DSBoxVars[4][0] * (index + DSBoxVars[4][1]) + DSBoxVars[4][2] ) % 256]] = index;
                DSBoxes[5][AES_SBox[( DSBoxVars[5][0] * (index + DSBoxVars[5][1]) + DSBoxVars[5][2] ) % 256]] = index;
                
            }
            
            return 1;
            break;
        
        default:
            return 0;
    }
}
//end sbox generation function

//Variable/Key initialization
//Dynamic SBox Var Selectors
uint8_t aValue(uint32_t x) {
    return A_Values[x % aSize];
}
uint8_t cValue(uint32_t x) {
    return C_Values[x % cSize];
}
uint8_t oValue(uint32_t x) {
    return (uint8_t)(x % oSize);
}

void initVars(uint8_t * key, uint32_t keysize) {
    keyslideInit(key, keysize);    
    int index = 0;
    int init = 0;
    for (init = 0; init < Keysize; ++init) {
        getNextExpandedKey(VAR);
    }

    aderive = getNextExpandedKey(VAR);
    for (index = 0; index < 6; ++index) {
        DSBoxVars[index][0] = A_Values[getNextExpandedKey(VAR) % aSize];
        DSBoxVars[index][1] = (uint8_t)(getNextExpandedKey(VAR) % oSize);
        DSBoxVars[index][2] = C_Values[getNextExpandedKey(VAR) % cSize];
    }
    cderive = getNextExpandedKey(VAR);
}

void finalXor(uint8_t * key, uint32_t keysize, uint8_t * out) {
    keyslideInit(key, keysize);
    uint32_t index = 0;
    uint32_t keyvalue;

    int init = 0;
    for (init = 0; init < Keysize; ++init) {
        getNextExpandedKey(FIN);
    }
    
    while(index < messageSize) {
        keyvalue = getNextExpandedKey(FIN);

        out[index] ^= ((uint8_t*)(&keyvalue))[0];
        ++index;
        
        if (index < messageSize) {
            out[index] ^= ((uint8_t*)(&keyvalue))[1];
            ++index;
            
             if (index < messageSize) {
                out[index] ^= ((uint8_t*)(&keyvalue))[2];
                ++index;
                
                if (index< messageSize) {
                    out[index] ^= ((uint8_t*)(&keyvalue))[3];
                    ++index;
                    
                 }
            }
        }
    }
}

void ivXor(uint8_t * out, uint8_t * iv, uint32_t ivsize) {
    uint32_t size = ivsize > messageSize ? messageSize : ivsize;
    uint32_t counter = 0;
    while (counter < size) {
        out[counter] ^= iv[counter];
        ++counter;
    }
}

//End Variable/Key initialization

//AES Mixing functions
uint8_t gmult2(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1 ) * 0x1b );
}

uint8_t gmult3(uint8_t x) {
    return gmult2(x) ^ x;
}

uint8_t gmult9(uint8_t x) {
    return gmult2(gmult2(gmult2(x))) ^ x;
}

uint8_t gmult11(uint8_t x) {
    return gmult2(gmult2(gmult2(x))) ^ gmult2(x) ^ x;
}

uint8_t gmult13(uint8_t x) {
    return gmult2(gmult2(gmult2(x))) ^ gmult2(gmult2(x)) ^ x;
}

uint8_t gmult14(uint8_t x) {
    return gmult2(gmult2(gmult2(x))) ^ gmult2(gmult2(x)) ^ gmult2(x);
}

void mix(uint8_t * in) {
    uint8_t temp[4];
    temp[0] = gmult2(in[0]) ^ gmult3(in[1]) ^ in[2] ^ in[3];
    temp[1] = in[0] ^ gmult2(in[1]) ^ gmult3(in[2]) ^ in[3];
    temp[2] = in[0] ^ in[1] ^ gmult2(in[2]) ^ gmult3(in[3]);
    temp[3] = gmult3(in[0]) ^ in[1] ^ in[2] ^ gmult2(in[3]);
    ((uint32_t*)in)[0] = ((uint32_t*)temp)[0];
}

void unmix(uint8_t * in) {
    uint8_t temp[4];
    temp[0] = gmult14(in[0]) ^ gmult11(in[1]) ^ gmult13(in[2]) ^ gmult9(in[3]);
    temp[1] = gmult9(in[0]) ^ gmult14(in[1]) ^ gmult11(in[2]) ^ gmult13(in[3]);
    temp[2] = gmult13(in[0]) ^ gmult9(in[1]) ^ gmult14(in[2]) ^ gmult11(in[3]);
    temp[3] = gmult11(in[0]) ^ gmult13(in[1]) ^ gmult9(in[2]) ^ gmult14(in[3]);
    ((uint32_t*)in)[0] = ((uint32_t*)temp)[0];
}

//End AES mixing functions

//NSize mix
void mixData(uint8_t * out, uint8_t r) {
    int32_t index = 0;
    uint8_t temp[4];
    while (index < messageSize) {
        temp[0] = out[index];
        temp[1] = out[(index + 1) % messageSize];
        temp[2] = out[(index + 2) % messageSize];
        temp[3] = out[(index + 3) % messageSize];
        
        mix(temp);
        
        out[index]                     = DSBoxes[r][temp[0]];
        out[(index + 1) % messageSize] = DSBoxes[(r + 1) % 6][temp[1]];
        out[(index + 2) % messageSize] = DSBoxes[(r + 2) % 6][temp[2]];
        out[(index + 3) % messageSize] = DSBoxes[(r + 3) % 6][temp[3]];
        index += MIXSTEP;
    }
}

void unmixData(uint8_t * out, uint32_t r) {
    int32_t index = messageSize - (messageSize % MIXSTEP == 0 ? MIXSTEP : messageSize % MIXSTEP);
    uint8_t temp[4];
    while (index >= 0) {
        temp[0] = DSBoxes[r][out[index]];
        temp[1] = DSBoxes[(r + 1) % 6][out[(index + 1) % messageSize]];
        temp[2] = DSBoxes[(r + 2) % 6][out[(index + 2) % messageSize]];
        temp[3] = DSBoxes[(r + 3) % 6][out[(index + 3) % messageSize]];
        
        unmix(temp);
        
        out[index]                     = temp[0];
        out[(index + 1) % messageSize] = temp[1];
        out[(index + 2) % messageSize] = temp[2];
        out[(index + 3) % messageSize] = temp[3];
        index -= MIXSTEP;
    }
}

//End NSize mix

//Main nsize encrypt and decrypt
int nSizeEncrypt(uint8_t* message, uint8_t* out, uint32_t size, uint8_t * key, uint32_t keysize, uint8_t * iv, uint32_t ivsize) {

    if (size > MAXBLOCKSIZE || size < MINBLOCKSIZE) {
        return -1;
    }
    messageSize = size;
    memcpy(out, message, messageSize);
    if (ivsize > 0) {
        ivXor(out, iv, ivsize);
    }
    initVars(key, keysize);
    sBoxBuilder(ENC);
    choosePerm();
        
    perm(out);
    mixData(out, 0);
    perm(out);
    mixData(out, 1);
    perm(out);
    mixData(out, 2);
    perm(out);
    mixData(out, 3);
    perm(out);
    mixData(out, 4);
    perm(out);
    mixData(out, 5);
    finalXor(key, keysize, out);
    
    return 0;
}

int nSizeDecrypt(uint8_t* message, uint8_t* out, uint32_t size, uint8_t * key, uint32_t keysize, uint8_t * iv, uint32_t ivsize) {

    if (size > MAXBLOCKSIZE || size < MINBLOCKSIZE) {
        return -1;
    }
    messageSize = size;
    memcpy(out, message, messageSize);
    initVars(key, keysize);
    sBoxBuilder(DEC);
    choosePerm();
    
    finalXor(key, keysize, out);
    unmixData(out,5);
    permInv(out);
    unmixData(out,4);
    permInv(out);
    unmixData(out,3);
    permInv(out);
    unmixData(out,2);
    permInv(out);
    unmixData(out,1);
    permInv(out);
    unmixData(out,0);
    permInv(out);
    
    if (ivsize > 0) {
        ivXor(out, iv, ivsize);
    }
    
    return 0;
}
//end nsize encrypt and decrypt
