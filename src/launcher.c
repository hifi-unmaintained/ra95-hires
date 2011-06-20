/*
 * Copyright (c) 2010, 2011 Toni Spets <toni.spets@iki.fi>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <windows.h>
#include <stdio.h>

void mem_write_code(HANDLE hProcess, DWORD address, BYTE *code, DWORD len, DWORD addr_ret)
{
    DWORD dwWritten;
    BYTE jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

    DWORD code_address = (DWORD)VirtualAllocEx(hProcess, NULL, len + 5 /* inc jmp <rel> */, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD code_rel_addr = code_address - (address + 5);
    DWORD addr_ret_rel = addr_ret - (code_address + len + 5);

    /* write JMP <code_rel_addr> to address */
    memcpy(jmp + 1, &code_rel_addr, 4);
    VirtualProtectEx(hProcess, (void *)address, 5, PAGE_EXECUTE_READWRITE, NULL);
    WriteProcessMemory(hProcess, (void *)address, jmp, 5, &dwWritten);

    /* write actual code */
    WriteProcessMemory(hProcess, (void *)code_address, code, len, &dwWritten);

    /* write jmp back */
    memcpy(jmp + 1, &addr_ret_rel, 4);
    VirtualProtectEx(hProcess, (void *)code_address + len, 5, PAGE_EXECUTE_READWRITE, NULL);
    WriteProcessMemory(hProcess, (void *)code_address + len, jmp, 5, &dwWritten);
}

void mem_write_byte(HANDLE hProcess, DWORD address, BYTE val)
{
    DWORD dwWritten;
    VirtualProtectEx(hProcess, (void *)address, sizeof(BYTE), PAGE_EXECUTE_READWRITE, NULL);
    WriteProcessMemory(hProcess, (void *)address, &val, sizeof(BYTE), &dwWritten);
}

void mem_write_dword(HANDLE hProcess, DWORD address, DWORD val)
{
    DWORD dwWritten;
    VirtualProtectEx(hProcess, (void *)address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, NULL);
    WriteProcessMemory(hProcess, (void *)address, &val, sizeof(DWORD), &dwWritten);
}

DWORD GetFileSizeByPath(const char *path)
{
    DWORD ret = 0;
    HANDLE hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile)
    {
        ret = GetFileSize(hFile, NULL);
        CloseHandle(hFile);
    }

    return ret;
}


BOOL FileExists(const char *path)
{
    FILE* file;
    if( (file = fopen(path, "r")) )
    {
        fclose(file);
        return TRUE;
    }
    return FALSE;
}

// replacement for dirname() POSIX function (also keeps internal copy of the path)
char *GetDirectory(const char *path)
{
    static char buf[MAX_PATH];
    char *ptr;
    strncpy(buf, path, MAX_PATH);
    ptr = strrchr(buf, '\\');
    if(ptr)
    {
        *(ptr+1) = 0;
        return buf;
    }

    return NULL;
}

char *GetFile(const char *path)
{
    static char buf[MAX_PATH];
    char *ptr;
    strncpy(buf, path, MAX_PATH);
    ptr = strrchr(buf, '\\');
    if(ptr)
    {
        return (ptr+1);
    }

    return buf;
}

int param_int(int argc, char **argv, char *key, int def)
{
    int i;

    for (i = 0; i < argc; i++)
    {
        if (stricmp(argv[i], key) == 0)
        {
            if (i+1 < argc)
            {
                return atoi(argv[i+1]);
            }
        }
    }

    return def;
}

int main(int argc, char **argv)
{
    const char *gameExe = "ra95.dat";
    const char *gameExe2 = "ra95.exe";
    const char *gameParams = ""; // will fix this later

    PROCESS_INFORMATION pInfo;
    STARTUPINFOA sInfo;

    char *gamePath = NULL;
    DWORD gameSize = 0;
    char gameParamsFull[MAX_PATH];

    int width = param_int(argc, argv, "-w", 1024);
    int height = param_int(argc, argv, "-h", 768);

    if (!FileExists(gameExe))
    {
        gameExe = gameExe2;
    }

    if (!FileExists(gameExe))
    {
        MessageBoxA(NULL, "Couldn't find RA95.DAT nor RA95.EXE, are we in the correct directory?", "Error", MB_OK|MB_ICONERROR);
        return 1;
    }

    gameSize = GetFileSizeByPath(gameExe);

    gamePath = GetDirectory(gameExe);
    if (gamePath)
    {
        SetCurrentDirectoryA(gamePath);
    }

    snprintf(gameParamsFull, MAX_PATH, "%s %s", GetFile(gameExe), gameParams);

    ZeroMemory(&sInfo, sizeof(STARTUPINFO));
    sInfo.cb = sizeof(sInfo);
    ZeroMemory(&pInfo, sizeof(PROCESS_INFORMATION));

    printf("%s\n", gameParamsFull);

    if (CreateProcessA(gameExe, (LPSTR)gameParamsFull, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &sInfo, &pInfo))
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE, FALSE, pInfo.dwProcessId);

        // width is the actual window width, height is both resolution switches from ini forced to hires
        mem_write_dword(hProcess, 0x006016B0, width);
        mem_write_dword(hProcess, 0x0055295F, height);
        mem_write_dword(hProcess, 0x00552966, height);

        // main menu background
        BYTE code[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,
            0x68, 0x00, 0x00, 0x00, 0x00,
            0x6A, 0x00,
            0x6A, 0x00
        };

        int top = height / 2 - 400 / 2;
        int left = width / 2 - 640 / 2;

        memcpy(code + 1, &top, 4);
        memcpy(code + 6, &left, 4);

        mem_write_code(hProcess, 0x005B3DBF, code, sizeof(code), 0x005B3DC7);

        // main menu version
        mem_write_dword(hProcess, 0x00501D63, width / 2 - 16);
        mem_write_dword(hProcess, 0x00501D68, height / 2);

        // main menu buttons
        mem_write_dword(hProcess, 0x00501DB9, width / 2 - 116);
        mem_write_dword(hProcess, 0x00501DBE, height / 2 - 26);

        // map scrolling
        mem_write_dword(hProcess, 0x00547119, width - 100);
        mem_write_dword(hProcess, 0x00547129, width);
        mem_write_dword(hProcess, 0x00547130, width);
        mem_write_dword(hProcess, 0x0054713D, width - 100);
        mem_write_dword(hProcess, 0x00547144, width / 2);
        mem_write_dword(hProcess, 0x00547177, height - 100);
        mem_write_dword(hProcess, 0x00547187, height);
        mem_write_dword(hProcess, 0x0054718E, height);
        mem_write_dword(hProcess, 0x00547193, width / 2);
        mem_write_dword(hProcess, 0x0054719A, height / 2); // this is used for both, interesting results in widescreen, adjust -100 offsets?

        // surrender dialog
        mem_write_dword(hProcess, 0x00503E3C, height / 2 + 25); // ok button offset top
        mem_write_dword(hProcess, 0x00503E4B, width / 2 - 100); // ok button offset left
        mem_write_dword(hProcess, 0x00503E66, height / 2 + 25); // cancel button offset top
        mem_write_dword(hProcess, 0x00503E75, width / 2 + 10); // cancel button offset left
        mem_write_dword(hProcess, 0x00503F05, width / 2 - 0x1E0 / 2); // dialog offset left, magic = dialog width
        mem_write_dword(hProcess, 0x00503F0D, height / 2 - 0x7E / 2); // dialog offset top, magic = dialog height
        mem_write_dword(hProcess, 0x00503F3A, height / 2 - 23); // caption offset from center of the screen (up)
        mem_write_dword(hProcess, 0x00503F3F, width / 2); // caption center offset from left

        /* game area width is multiples of 24 and the hud needs to be placed exactly after that, thus, this crappy math */
        width = ((width - 160) / 24 * 24) + 160;

        // buffer1 dimensions
        mem_write_dword(hProcess, 0x00552629, height);
        mem_write_dword(hProcess, 0x00552638, width);

        // buffer2 dimensions
        mem_write_dword(hProcess, 0x00552646, height);
        mem_write_dword(hProcess, 0x00552655, width);

        // power bar background position
        mem_write_dword(hProcess, 0x00527736, width - 160);
        mem_write_dword(hProcess, 0x0052775C, width - 160);

        // side bar background position
        mem_write_dword(hProcess, 0x0054D7CB, width - 160);
        mem_write_dword(hProcess, 0x0054D7F1, width - 160);
        mem_write_dword(hProcess, 0x0054D816, width - 160);

        // credits tab background position
        mem_write_dword(hProcess, 0x00553758, width - 160);

        // repair button left offset
        mem_write_dword(hProcess, 0x0054D166, width - 142);

        // sell button left offset
        mem_write_dword(hProcess, 0x0054D1DA, width - 97);

        // map button left offset
        mem_write_dword(hProcess, 0x0054D238, width - 52);

        // side bar strip offset left
        mem_write_dword(hProcess, 0x0054D00F, width - 144);
        // side bar strip offset left + width (70)
        mem_write_dword(hProcess, 0x0054D023, (width - 144) + 70);

        // side bar strip icons offset
        mem_write_dword(hProcess, 0x0054D08C, width - 144);

        // power indicator (darker shadow)
        mem_write_dword(hProcess, 0x005278A4, width - 150);
        mem_write_dword(hProcess, 0x005278AE, width - 149);

        // power indicator (light)
        mem_write_dword(hProcess, 0x00527A4D, width - 148);
        mem_write_dword(hProcess, 0x00527A52, width - 147);

        // power usage indicator
        mem_write_dword(hProcess, 0x00527C0F, width - 158);

        // power bar caption position
        mem_write_dword(hProcess, 0x005275D9, width - 160);

        // width of the game area, in tiles, 1 tile = 24px
        mem_write_byte(hProcess, 0x0054DB15, (width - 160) / 24);

        // very ugly hack for the blinking cursor when on original sidebar area
        // though, I see no point in this code, the strip bar does not have any help caption text what is what this function seems to show
        mem_write_byte(hProcess, 0x0054F380, 0xC3); // RETN in SidebarClass::SBGadgetClass::Action (VERY WRONG)

        // Shake_The_Screen, when stuff blows up
        mem_write_dword(hProcess, 0x004AB8A4, width);
        mem_write_dword(hProcess, 0x004AB8A9, height - 2);
        mem_write_dword(hProcess, 0x004AB8C9, width);
        mem_write_dword(hProcess, 0x004ABBE0, height - 2);
        mem_write_dword(hProcess, 0x004ABBFB, width);

        ResumeThread(pInfo.hThread);

        WaitForSingleObject(hProcess, INFINITE);

        CloseHandle(hProcess);
        CloseHandle(pInfo.hProcess);
        CloseHandle(pInfo.hThread);
        return 0;
    }
    else
    {
        MessageBoxA(NULL, "Couldn't launch RA95, thus not patched", "Error", MB_OK|MB_ICONERROR);
        return 1;
    }
}
