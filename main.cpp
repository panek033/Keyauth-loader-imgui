#include "Main.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <winbase.h>
#include <tchar.h>
#include "auth.hpp"
#include <CommCtrl.h>

#include "font/font.h"
#include "font/icons.h"


#include "xorstr.hpp"
#include <tlhelp32.h>
#include <thread>
#include <random>


#include <Psapi.h>
#include <chrono>
#include <future>

#pragma comment(lib, "psapi.lib")

IDirect3DTexture9* masterlogo;




using namespace KeyAuth;


std::string name = XorStr(""); //Application name found in application settings
std::string ownerid = XorStr(""); //Owner ID Found in user settings
std::string secret = XorStr(""); //Application secret found in Application settings
std::string version = XorStr("1.9"); // Version can be changed but is not really important
std::string url = "https://keyauth.win/api/1.1/"; // change if you're self-hosting
std::string sslPin = "ssl pin key (optional)"; // don't change unless you intend to pin public certificate key. you can get here in the "Pin SHA256" field https://www.ssllabs.com/ssltest/analyze.html?d=ke
api KeyAuthApp(name, ownerid, secret, version, url, sslPin);



static int width = 350;
static int height = 200;

char PassWord[20] = "";
char Licence[50] = "";
char UserName[20] = "";
char RgPassWord[20] = "";
char RgUserName[20] = "";

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);


bool LoginCheck = false;

typedef NTSTATUS(WINAPI* lpQueryInfo)(HANDLE, LONG, PVOID, ULONG, PULONG);

//all over the internet, i didnt make this
PVOID DetourFunc(BYTE* src, const BYTE* dst, const int len)
{
    BYTE* jmp = (BYTE*)malloc(len + 5); DWORD dwback;
    VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwback);
    memcpy(jmp, src, len); jmp += len; jmp[0] = 0xE9;

    *(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5; src[0] = 0xE9;
    *(DWORD*)(src + 1) = (DWORD)(dst - src) - 5;

    VirtualProtect(src, len, dwback, &dwback);
    return (jmp - len);
}

//not proper way to detour, but since we arent continuing thread context we dont return context.
//to continue thread execution after detour do something like this I think
//void CaptureThread(PCONTEXT context, PVOID arg1, PVOID arg2)
//return (new ldrThunk) -> Thunk name(PCONTEXT context, PVOID arg1, PVOID arg2) <- current thread context.

void CaptureThread()
{
    //getting thread start address isnt needed, it just gives extra information on the thread stack which allows you to see some potential injection methods used
    auto ThreadStartAddr = [](HANDLE hThread) -> DWORD {

        //Hook NtQueryInformationThread
        lpQueryInfo ThreadInformation = (lpQueryInfo)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

        DWORD StartAddress;
        //Get information from current thread handle
        ThreadInformation(hThread, 9, &StartAddress, sizeof(DWORD), NULL);

        return StartAddress;
    };

    //Gets handle of current thread. (HANDLE)(LONG_PTR)-1 is handle of CurrentProcess if you need it
    HANDLE CurrentThread = (HANDLE)(LONG_PTR)-2;
    //Gets thread information from thread handle.
    DWORD  StartAddress = ThreadStartAddr(CurrentThread);

    //address 0x7626B0E0 is a static address which is assigned to exit thread of the application
    //we need to whitelist it otherwise you cant close the application from usermode
    if (StartAddress != 0x7626B0E0) {
        printf("\n[+] Block [TID: %d][Start Address: %p]", (DWORD)GetThreadId(CurrentThread), (CHAR*)StartAddress);
        //Exits thread and stops potential code execution
        //if you dont term thread it will crash if you dont handle context properly
        if (!TerminateThread(CurrentThread, 0xC0C)) exit(0);
    }
    else exit(0);
}

BOOL HookLdrInitializeThunk()
{
    //Gets handle of ntdll.dll in the current process, which allows us to detour LdrInitializeThunk calls in given context
    HMODULE hModule = LoadLibraryA("ntdll.dll");
    if (hModule && (PBYTE)GetProcAddress(hModule, reinterpret_cast<LPCSTR>("LdrInitializeThunk")))
    {
        DetourFunc((PBYTE)GetProcAddress(hModule, "LdrInitializeThunk"), (PBYTE)CaptureThread, 5);
        return TRUE;
    }
    else return FALSE;
}

//you can also hook RtlGetFullPathName_U to get path of module loaded, but it was not worth it because 
//RtlGetFullPathName_U only get path after module was loaded which can be a insecurity (maybe).
//though hooking RtlGetFullPathName_U doesnt point to the right location on some manual map injectors but it works for Xenos and AlisAlias injector

// This was made by ShadowMonster#2247 So credit to him

int AntiCrack()
{
    //Havent tested all kernel injection methods
    if (HookLdrInitializeThunk()) printf("[+] Hook Success");
    else printf("[-] Hook Failed");

    std::promise<void>().get_future().wait();

    return 0;
}


int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{




    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, LOADER_BRAND, NULL };
    RegisterClassEx(&wc);
    main_hwnd = CreateWindow(wc.lpszClassName, LOADER_BRAND, WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);


    if (!CreateDeviceD3D(main_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }


    ShowWindow(main_hwnd, SW_HIDE);
    UpdateWindow(main_hwnd);


    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    ImGui::StyleColorsDark();




    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {


        void Theme(); {
            ImGuiStyle& style = ImGui::GetStyle();

            style.Colors[ImGuiCol_TitleBg] = ImColor(2, 2, 2, 225);
            style.Colors[ImGuiCol_TitleBgCollapsed] = ImColor(2, 2, 2, 225);
            style.Colors[ImGuiCol_TitleBgActive] = ImColor(2, 2, 2, 225);
            style.Colors[ImGuiCol_WindowBg] = ImColor(2, 2, 2, 225);
            style.Colors[ImGuiCol_Button] = ImColor(28, 28, 28);
            style.Colors[ImGuiCol_ButtonActive] = ImColor(38, 38, 38);
            style.Colors[ImGuiCol_ButtonHovered] = ImColor(38, 38, 38);
            style.Colors[ImGuiCol_CheckMark] = ImColor(255, 255, 255, 255);
            style.Colors[ImGuiCol_FrameBg] = ImColor(38, 38, 38);
            style.Colors[ImGuiCol_FrameBgActive] = ImColor(42, 42, 42);
            style.Colors[ImGuiCol_FrameBgHovered] = ImColor(39, 39, 39);
            style.Colors[ImGuiCol_Header] = ImColor(24, 24, 24, 255);
            style.Colors[ImGuiCol_HeaderActive] = ImColor(54, 53, 55);
            style.Colors[ImGuiCol_HeaderHovered] = ImColor(24, 24, 24, 100);
            style.Colors[ImGuiCol_ResizeGrip] = ImColor(51, 49, 50, 255);
            style.Colors[ImGuiCol_ResizeGripActive] = ImColor(54, 53, 55);
            style.Colors[ImGuiCol_ResizeGripHovered] = ImColor(51, 49, 50, 255);
            style.Colors[ImGuiCol_SliderGrab] = ImColor(249, 79, 49, 255);
            style.Colors[ImGuiCol_SliderGrabActive] = ImColor(249, 79, 49, 255);
            style.Colors[ImGuiCol_TabActive] = ImColor(32, 36, 47);
            style.Colors[ImGuiCol_Tab] = ImColor(32, 36, 47);
            style.Colors[ImGuiCol_Border] = ImColor(2, 2, 2, 225);
            style.Colors[ImGuiCol_Separator] = ImColor(54, 54, 54);
            style.Colors[ImGuiCol_SeparatorActive] = ImColor(54, 54, 54);
            style.Colors[ImGuiCol_SeparatorHovered] = ImColor(54, 54, 54);

            style.WindowPadding = ImVec2(4, 4);
            style.WindowBorderSize = 0.f;

            style.FramePadding = ImVec2(8, 6);
            style.FrameRounding = 8.f;
            style.FrameBorderSize = 1.f;

        }
    }

    ImGui_ImplWin32_Init(main_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };
    ImFontConfig icons_config;

    ImFontConfig CustomFont;
    CustomFont.FontDataOwnedByAtlas = false;

    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.OversampleH = 3;
    icons_config.OversampleV = 3;

    io.Fonts->AddFontFromMemoryTTF(const_cast<std::uint8_t*>(Custom), sizeof(Custom), 20, &CustomFont);
    io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 32.5f, &icons_config, icons_ranges);

    io.Fonts->AddFontDefault();




    DWORD window_flags = ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoResize;
    RECT screen_rect;
    GetWindowRect(GetDesktopWindow(), &screen_rect);
    auto x = float(screen_rect.right - width) / 2.f;
    auto y = float(screen_rect.bottom - height) / 2.f;

    static int Tabs = 2;

    static int TAB = 1;

    void hideStartupConsoleOnce();
    {
        HWND Stealth;
        AllocConsole();
        Stealth = FindWindowA("HusClass", NULL);
        ShowWindow(Stealth, 0);
    }

    bool InfWindow = false;

    KeyAuthApp.init();

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT && !LoginCheck)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }


        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        {
            //login form test
            bool login = true;

            static int switchTabs = 3;

            


            ImGui::SetNextWindowSize(ImVec2(740, 428));
            ImGui::Begin("Hus Loader", &loader_active, window_flags);
            {
                ImGui::BeginChild("main", ImVec2(740, 388), false,ImGuiWindowFlags_NoScrollbar);
                {


                    //UWU PARTCVILES 

                    ImDrawList* drawList = ImGui::GetWindowDrawList();			//draws like foreground does but behind the imgui stuff. Ideal

                    //particle properties
                    static const int numParticles = 115;
                    static ImVec2 particlePositions[numParticles];
                    static ImVec2 particleDistance;
                    static ImVec2 particleVelocities[numParticles];

                    static bool initialized = false;
                    if (!initialized)
                    {
                        for (int i = 0; i < numParticles; ++i)
                        {
                            particlePositions[i] = ImVec2(
                                ImGui::GetWindowPos().x + ImGui::GetWindowSize().x * static_cast<float>(rand()) / RAND_MAX,
                                ImGui::GetWindowPos().y + ImGui::GetWindowSize().y * static_cast<float>(rand()) / RAND_MAX
                            );

                            particleVelocities[i] = ImVec2(
                                static_cast<float>((rand() % 11) - 5),
                                static_cast<float>((rand() % 11) - 5)
                            );

                        }

                        initialized = true;
                    }

                    ImVec2 cursorPos = ImGui::GetIO().MousePos;
                    for (int i = 0; i < numParticles; ++i)
                    {
                        //draw lines to particles
                        for (int j = i + 1; j < numParticles; ++j)
                        {
                            float distance = std::hypotf(particlePositions[j].x - particlePositions[i].x, particlePositions[j].y - particlePositions[i].y);
                            float opacity = 1.0f - (distance / 55.0f);  // opacity cahnge

                            if (opacity > 0.0f)
                            {
                                ImU32 lineColor = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, opacity));
                                drawList->AddLine(particlePositions[i], particlePositions[j], lineColor);
                            }
                        }

                        //draw lines to cursor
                        float distanceToCursor = std::hypotf(cursorPos.x - particlePositions[i].x, cursorPos.y - particlePositions[i].y);
                        float opacityToCursor = 1.0f - (distanceToCursor / 52.0f);  // Adjust the divisor to control the opacity change

                        if (opacityToCursor > 0.0f)
                        {
                            ImU32 lineColorToCursor = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, opacityToCursor));
                            drawList->AddLine(cursorPos, particlePositions[i], lineColorToCursor);
                        }
                    }

                    //update and render particles
                    float deltaTime = ImGui::GetIO().DeltaTime;
                    for (int i = 0; i < numParticles; ++i)
                    {
                        particlePositions[i].x += particleVelocities[i].x * deltaTime;
                        particlePositions[i].y += particleVelocities[i].y * deltaTime;

                        // Stay in window
                        if (particlePositions[i].x < ImGui::GetWindowPos().x)
                            particlePositions[i].x = ImGui::GetWindowPos().x + ImGui::GetWindowSize().x;
                        else if (particlePositions[i].x > ImGui::GetWindowPos().x + ImGui::GetWindowSize().x)
                            particlePositions[i].x = ImGui::GetWindowPos().x;

                        if (particlePositions[i].y < ImGui::GetWindowPos().y)
                            particlePositions[i].y = ImGui::GetWindowPos().y + ImGui::GetWindowSize().y;
                        else if (particlePositions[i].y > ImGui::GetWindowPos().y + ImGui::GetWindowSize().y)
                            particlePositions[i].y = ImGui::GetWindowPos().y;

                        ImU32 particleColour = ImGui::ColorConvertFloat4ToU32(ImVec4(255, 255, 255, 255));

                        //render particles behind components
                        drawList->AddCircleFilled(particlePositions[i], 1.5f, particleColour);
                    }

                    if (TAB == 1)
                    {

                        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.054, 0.054, 0.054, 245));
                        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.082, 0.078, 0.078, 255));
                        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 3.f);
                        {
                            ImGui::SetCursorPos(ImVec2(212, 53));
                            ImGui::BeginChild("##MainPanel", ImVec2(300, 260), true, ImGuiWindowFlags_NoScrollbar);
                            {
                                    ImGui::SetCursorPos(ImVec2(138, 20));
                                    ImGui::TextDisabled(ICON_FA_HOME"");

                                    ImGui::SetCursorPos(ImVec2(67, 35));
                                    ImGui::Text("Log into your account");

                                    ImGui::PushItemWidth(260.f);
                                    {
                                        ImGui::SetCursorPos(ImVec2(22, 79));
                                        ImGui::TextDisabled("Key");

                                        ImGui::SetCursorPos(ImVec2(20, 100));
                                        ImGui::InputText("  ", Licence, IM_ARRAYSIZE(Licence));
                                    }
                                    ImGui::PopItemWidth();


                                    ImGui::SetCursorPos(ImVec2(102, 159));
                                    ImGui::Text("dsc.gg/rive");

                                    ImGui::SetCursorPos(ImVec2(22, 210));
                                    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.f);
                                    if (ImGui::Button("Login", ImVec2(260.f, 30.f)))
                                    {
                                        KeyAuthApp.license(Licence);
                                        if (!KeyAuthApp.data.success)
                                        {
                                            MessageBox(NULL, TEXT("Key doesnt exist !"), TEXT("Hus Loader"), MB_OK);
                                            exit(0);
                                        }
                                        Tabs = 2;
                                        TAB = 2;
                                    }
                                    ImGui::PopStyleVar();
                            }
                            ImGui::EndChild();
                        }
                        ImGui::PopStyleColor(2);
                        ImGui::PopStyleVar(1);

                        ImGui::SetCursorPos(ImVec2(5, 370));
                        ImGui::TextDisabled("Made by Hus for skids <3 Lov u all");
                    }
                    


                    if (TAB == 2) {
                        static bool Sc = true;
                        bool show = false;
                        static double s0 = 0.0;





                        //TABS DO NOT TOUCH YET


                        static int switchTabs = 3;

                        if (ImGui::Button(ICON_FA_EYE "Main", ImVec2(100.0f, 40.0f)))
                            switchTabs = 0;

                        switch (switchTabs) {
                        case 0:
                            ImGui::Text("dsc.gg/rive");
                            break;
                        }



                        //THIS WILL BE THE MAIN CODE FOR THE MISC FILE DO NOT TOUCH OR EDIT AFTER DONE WITH IT


                        if (switchTabs == 1) {
                        }
                        //Extra tab were you put your extra features

                        if (switchTabs == 0) {
                        }

                        //main code gose here
                        void InfLog();
                        {
                            RECT screen_rect;
                            GetWindowRect(GetDesktopWindow(), &screen_rect);
                            auto x = float(screen_rect.right - width) / 2.f;
                            auto y = float(screen_rect.bottom - height) / 2.f;


                            ImGui::End();
                        }
                        if (switchTabs == 2) {
                            //settings
                        }

                    
                        
                    }
                }
            }                      
            ImGui::End();
        }
        ImGui::EndFrame();

        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }


        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);


        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            ResetDevice();
        }
        if (!loader_active) {
            msg.message = WM_QUIT;
        }
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(main_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);

}







































