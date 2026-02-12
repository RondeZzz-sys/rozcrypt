#define SHA256_DIGEST_SIZE 32
#define PBKDF2_ITERATIONS 10000
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) ( \
    a += b, d ^= a, d = ROTL(d, 16), \
    c += d, b ^= c, b = ROTL(b, 12), \
    a += b, d ^= a, d = ROTL(d, 8), \
    c += d, b ^= c, b = ROTL(b, 7))
void chacha20_block(uint32_t out[16], uint32_t const in[16]) {
    int i;
    for (i = 0; i < 16; ++i) out[i] = in[i];
    for (i = 0; i < 8; ++i) {
        QR(out[0], out[4], out[ 8], out[12]);
        QR(out[1], out[5], out[ 9], out[13]);
        QR(out[2], out[6], out[10], out[14]);
        QR(out[3], out[7], out[11], out[15]);
        QR(out[0], out[5], out[10], out[15]);
        QR(out[1], out[6], out[11], out[12]);
        QR(out[2], out[7], out[ 8], out[13]);
        QR(out[3], out[4], out[ 9], out[14]);
    }
    for (i = 0; i < 16; ++i) out[i] += in[i];
}
#define CLR_BACK      RGB(20, 20, 20)
#define CLR_TEXT      RGB(0, 255, 127)
#define CLR_EDIT_BK   RGB(35, 35, 35)
#define CLR_FRAME     RGB(0, 200, 100)
HWND hEdit, hProgress, hStatus, hInfoMsg;
HBRUSH hBrushBack, hBrushEdit;
HFONT hFontMain, hFontLabel, hFontSmall;
void update_visuals(int pos) {
    char buf[64];
    sprintf(buf, "BLOCK AUTH: [0x%08X%08X%08X]", rand(), rand(), rand());
    SetWindowTextA(hInfoMsg, buf);
    SendMessage(hProgress, PBM_SETPOS, (WPARAM)pos, 0);
    UpdateWindow(hProgress);
    UpdateWindow(hInfoMsg);
}
void derive_key(const char* password, BYTE* key) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD key_len = 32;
    SecureZeroMemory(key, key_len);
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (const BYTE*)password, (DWORD)strlen(password), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, key, &key_len, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
void generate_nonce(BYTE* nonce, size_t len) {
    HCRYPTPROV hProv = 0;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hProv, (DWORD)len, nonce);
    CryptReleaseContext(hProv, 0);
}
void hmac_sha256(const BYTE* key, DWORD key_len, const BYTE* data, DWORD data_len, BYTE* out_hmac) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash);
    HMAC_INFO hmacInfo = { CALG_SHA_256 };
    CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0);
    CryptHashData(hHash, key, key_len, 0);
    CryptHashData(hHash, data, data_len, 0);
    DWORD hmac_len = SHA256_DIGEST_SIZE;
    CryptGetHashParam(hHash, HP_HASHVAL, out_hmac, &hmac_len, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
void process_file(const char* path, const char* password) {
    if (strlen(password) == 0) {
        MessageBoxA(NULL, "Password cannot be empty.", "Error", MB_ICONERROR);
        return;
    }
    BYTE key[32];
    derive_key(password, key);
    char out_path[MAX_PATH];
    int is_dec = (strstr(path, ".rozcrypt") != NULL);
    if (is_dec) {
        strncpy(out_path, path, strlen(path) - 9);
        out_path[strlen(path) - 9] = '\0';
    } else {
        snprintf(out_path, MAX_PATH, "%s.rozcrypt", path);
    }
    FILE* f_in = fopen(path, "rb");
    if (!f_in) {
        SecureZeroMemory(key, sizeof(key));
        return;
    }
    _fseeki64(f_in, 0, SEEK_END);
    long long f_size = _ftelli64(f_in);
    _fseeki64(f_in, 0, SEEK_SET);
    if (is_dec) {
        if (f_size < 12 + SHA256_DIGEST_SIZE) {
            fclose(f_in);
            MessageBoxA(NULL, "File too small or corrupted.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        BYTE nonce[12];
        if (fread(nonce, 1, 12, f_in) != 12) {
            fclose(f_in);
            MessageBoxA(NULL, "Failed to read nonce.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        long long data_end = f_size - SHA256_DIGEST_SIZE;
        long long cipher_len = data_end - 12;
        BYTE* encrypted_data = (BYTE*)malloc((size_t)data_end);
        if (!encrypted_data) {
            fclose(f_in);
            MessageBoxA(NULL, "Memory allocation failed.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        _fseeki64(f_in, 0, SEEK_SET);
        if (fread(encrypted_data, 1, (size_t)data_end, f_in) != (size_t)data_end) {
            free(encrypted_data);
            fclose(f_in);
            MessageBoxA(NULL, "Failed to read encrypted data.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        BYTE hmac_file[SHA256_DIGEST_SIZE];
        _fseeki64(f_in, data_end, SEEK_SET);
        if (fread(hmac_file, 1, SHA256_DIGEST_SIZE, f_in) != SHA256_DIGEST_SIZE) {
            free(encrypted_data);
            fclose(f_in);
            MessageBoxA(NULL, "Failed to read HMAC.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        fclose(f_in);
        BYTE key_hmac[32];
        derive_key(password, key_hmac);
        BYTE hmac_calc[SHA256_DIGEST_SIZE];
        hmac_sha256(key_hmac, 32, encrypted_data, (DWORD)data_end, hmac_calc);
        SecureZeroMemory(key_hmac, sizeof(key_hmac));
        if (memcmp(hmac_calc, hmac_file, SHA256_DIGEST_SIZE) != 0) {
            free(encrypted_data);
            _unlink(out_path);
            MessageBoxA(NULL, "Decryption failed: Invalid password or corrupted file.", "Error", MB_ICONERROR);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        uint32_t ctx[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0,0,0,0, 0,0,0,0, 0,0,0,0
        };
        memcpy(&ctx[4], key, 32);
        memcpy(&ctx[13], nonce, 12);
        ctx[12] = 0;
        FILE* f_out = fopen(out_path, "wb");
        if (!f_out) {
            free(encrypted_data);
            SecureZeroMemory(key, sizeof(key));
            MessageBoxA(NULL, "Cannot create output file.", "Error", MB_ICONERROR);
            return;
        }
        BYTE* cipher_ptr = encrypted_data + 12;
        long long remaining = cipher_len;
        uint8_t block[64];
        uint32_t output[16];
        long long processed = 0;
        while (remaining > 0) {
            size_t chunk = (remaining > 64) ? 64 : (size_t)remaining;
            memcpy(block, cipher_ptr, chunk);
            chacha20_block(output, ctx);
            for (size_t i = 0; i < chunk; i++)
                block[i] ^= ((uint8_t*)output)[i];
            fwrite(block, 1, chunk, f_out);
            ctx[12]++;
            cipher_ptr += chunk;
            remaining -= chunk;
            processed += chunk;
            if (cipher_len > 0)
                update_visuals((int)((processed * 100) / cipher_len));
        }
        fclose(f_out);
        free(encrypted_data);
        SecureZeroMemory(key, sizeof(key));
    }
    else {
        BYTE nonce[12];
        generate_nonce(nonce, 12);
        uint32_t ctx[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0,0,0,0, 0,0,0,0, 0,0,0,0
        };
        memcpy(&ctx[4], key, 32);
        memcpy(&ctx[13], nonce, 12);
        ctx[12] = 0;
        FILE* f_out = fopen(out_path, "wb");
        if (!f_out) {
            fclose(f_in);
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        fwrite(nonce, 1, 12, f_out);
        uint8_t block[64];
        uint32_t output[16];
        size_t n;
        long long processed = 0;
        while ((n = fread(block, 1, 64, f_in)) > 0) {
            chacha20_block(output, ctx);
            for (size_t i = 0; i < n; i++)
                block[i] ^= ((uint8_t*)output)[i];
            fwrite(block, 1, n, f_out);
            ctx[12]++;
            processed += n;
            if (f_size > 0)
                update_visuals((int)((processed * 100) / f_size));
        }
        fclose(f_in);
        fclose(f_out);
        f_out = fopen(out_path, "rb");
        if (!f_out) {
            SecureZeroMemory(key, sizeof(key));
            return;
        }
        _fseeki64(f_out, 0, SEEK_END);
        long long enc_size = _ftelli64(f_out);
        _fseeki64(f_out, 0, SEEK_SET);
        BYTE* enc_data = (BYTE*)malloc((size_t)enc_size);
        if (enc_data) {
            fread(enc_data, 1, (size_t)enc_size, f_out);
            fclose(f_out);
            BYTE key_hmac[32];
            derive_key(password, key_hmac);
            BYTE hmac[SHA256_DIGEST_SIZE];
            hmac_sha256(key_hmac, 32, enc_data, (DWORD)enc_size, hmac);
            SecureZeroMemory(key_hmac, sizeof(key_hmac));
            f_out = fopen(out_path, "ab");
            if (f_out) {
                fwrite(hmac, 1, SHA256_DIGEST_SIZE, f_out);
                fclose(f_out);
            }
            free(enc_data);
        }
        SecureZeroMemory(key, sizeof(key));
    }
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            srand((unsigned int)GetTickCount());
            hBrushBack = CreateSolidBrush(CLR_BACK);
            hBrushEdit = CreateSolidBrush(CLR_EDIT_BK);
            hFontMain = CreateFontA(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    ANSI_CHARSET, 0, 0, DEFAULT_QUALITY, 0, "Consolas");
            hFontLabel = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                     ANSI_CHARSET, 0, 0, DEFAULT_QUALITY, 0, "Segoe UI");
            hFontSmall = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                     ANSI_CHARSET, 0, 0, DEFAULT_QUALITY, 0, "Consolas");
            CreateWindowA("STATIC", "ENCRYPTION KEY:",
                          WS_VISIBLE | WS_CHILD, 50, 35, 500, 20, hwnd, NULL, NULL, NULL);
            SendMessage(GetDlgItem(hwnd, 0), WM_SETFONT, (WPARAM)hFontLabel, TRUE);
            hEdit = CreateWindowExA(0, "EDIT", "MySecretKey123",
                                    WS_VISIBLE | WS_CHILD | ES_PASSWORD | ES_CENTER,
                                    50, 60, 500, 40, hwnd, NULL, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFontMain, TRUE);
            CreateWindowA("STATIC", "",
                          WS_VISIBLE | WS_CHILD | SS_BLACKFRAME,
                          48, 120, 504, 150, hwnd, NULL, NULL, NULL);
            hStatus = CreateWindowA("STATIC", "\n\n   Drag & drop files here",
                                    WS_VISIBLE | WS_CHILD | SS_CENTER,
                                    50, 122, 500, 146, hwnd, NULL, NULL, NULL);
            SendMessage(hStatus, WM_SETFONT, (WPARAM)hFontMain, TRUE);
            hInfoMsg = CreateWindowA("STATIC", "READY",
                                     WS_VISIBLE | WS_CHILD | SS_LEFT,
                                     50, 275, 500, 15, hwnd, NULL, NULL, NULL);
            SendMessage(hInfoMsg, WM_SETFONT, (WPARAM)hFontSmall, TRUE);
            hProgress = CreateWindowExA(0, PROGRESS_CLASS, NULL,
                                        WS_CHILD | PBS_SMOOTH,
                                        50, 310, 500, 6, hwnd, NULL, NULL, NULL);
            SetWindowTheme(hProgress, L"", L"");
            SendMessage(hProgress, PBM_SETBKCOLOR, 0, (LPARAM)CLR_BACK);
            SendMessage(hProgress, PBM_SETBARCOLOR, 0, (LPARAM)CLR_TEXT);
            ShowWindow(hProgress, SW_HIDE);
            DragAcceptFiles(hwnd, TRUE);
            break;
        case WM_CTLCOLORSTATIC:
            SetTextColor((HDC)wParam, CLR_TEXT);
            SetBkColor((HDC)wParam, CLR_BACK);
            return (LRESULT)hBrushBack;
        case WM_CTLCOLOREDIT:
            SetTextColor((HDC)wParam, CLR_TEXT);
            SetBkColor((HDC)wParam, CLR_EDIT_BK);
            return (LRESULT)hBrushEdit;
        case WM_ERASEBKGND: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect((HDC)wParam, &rc, hBrushBack);
            return 1;
        }
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            char path[MAX_PATH];
            char key[33] = {0};
            GetWindowTextA(hEdit, key, 32);
            ShowWindow(hProgress, SW_SHOW);
            SetWindowTextA(hStatus, "\n\n   PROCESSING...");
            UINT count = DragQueryFileA(hDrop, 0xFFFFFFFF, NULL, 0);
            for (UINT i = 0; i < count; i++) {
                DragQueryFileA(hDrop, i, path, MAX_PATH);
                process_file(path, key);
                UpdateWindow(hwnd);
            }
            DragFinish(hDrop);
            SendMessage(hProgress, PBM_SETPOS, 100, 0);
            SetWindowTextA(hStatus, "\n\n   DONE.");
            SetWindowTextA(hInfoMsg, "All files processed. Original files kept.");
            SetTimer(hwnd, 1, 2500, NULL);
            break;
        }
        case WM_TIMER:
            if (wParam == 1) {
                SetWindowTextA(hStatus, "\n\n   Drag & drop files here");
                SetWindowTextA(hInfoMsg, "READY");
                ShowWindow(hProgress, SW_HIDE);
                SendMessage(hProgress, PBM_SETPOS, 0, 0);
                KillTimer(hwnd, 1);
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    InitCommonControls();
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "rozcrypt_class";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(0, "rozcrypt_class", "rozcrypt — ChaCha20 File Encryptor",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 616, 399,
                                NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nShow);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}