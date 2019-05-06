using System;
//for StringBuilder
using System.Text;
//for DllImport
using System.Runtime.InteropServices;
//for IntPtr to Point structur
using System.Drawing;

namespace DLLImports
{
    public static class User32DLL
    {
        #region DLL_Imports

        #region GetActiveWindow_done
        /*      
         *      Syntax
         *      HWND GetActiveWindow();
         *      
         *      Return Value
         *      Type: HWND - a handle to the active window or null
         */
        /// <summary>
        /// GetActiveWindow() from winuser.h / user32.dll
        /// </summary>
        /// <returns> a handle to the active window or null </returns>
        [DllImport("user32.dll", EntryPoint = "GetActiveWindow")]
        public static extern IntPtr GetActiveWindow();
        #endregion

        #region GetDesktopWindow_done
        /*      
         *      Syntax
         *      HWND GetDesktopWindow();
         *      
         *      Return Value
         *      Type: HWND - a handle to the desktop window
         */
        /// <summary>
        /// GetDesktopWindow() from winuser.h / user32.dll
        /// </summary>
        /// <returns> a handle to the desktop window </returns>
        [DllImport("user32.dll", EntryPoint = "GetDesktopWindow")]
        public static extern IntPtr GetDesktopWindow();
        #endregion

        #region GetForegroundWindow_done
        /*      
         *      Syntax
         *      HWND GetForegroundWindow();
         *      
         *      Return Value
         *      Type: HWND - a handle to the foreground window or null
         */
        /// <summary>
        /// GetForegroundWindow() from winuser.h / user32.dll
        /// </summary>
        /// <returns> a handle to the foreground window or null </returns>
        [DllImport("user32.dll", EntryPoint = "GetForegroundWindow")]
        public static extern IntPtr GetForegroundWindow();
        #endregion

        #region GetWindowInfo_done
        /*      
         *      Syntax
         *      BOOL GetWindowInfo( HWND hWnd, PWINDOWINFO pwi );
         *      
         *      Parameters
         *      Type: HWND - A handle to the window whose information is to be retrieved
         *      Type: PWINDOWINFO - A pointer to a WINDOWINFO structure to receive the information.
         *                          Note that you must set the cbSize member to sizeof(WINDOWINFO) before calling this function
         *                          
         *      Return Value
         *      Type: BOOL - failed returns zero, succeeded returns nonzero
         */
        /// <summary>
        /// GetWindowInfo() from winuser.h / user32.dll
        /// 
        /// Note that you must set the cbSize member to sizeof(WINDOWINFO) before calling this function
        /// 
        /// </summary>
        /// <param name="hWnd"> a handle to the window whose information is to be retrieved </param>
        /// <param name="pwi"> a pointer to a WINDOWINFO structure to receive the information </param>
        /// <returns> returns zero if fails and nonzero if succeeds </returns>
        [DllImport("user32.dll", EntryPoint = "GetWindowInfo", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowInfo(IntPtr hWnd, ref WINDOWINFO pwi);
        #endregion

        #region GetWindowRect_done
        /*      
         *      Syntax
         *      BOOL GetWindowRect( HWND hWnd, LPRECT lpRect );
         *      
         *      Parameters
         *      Type: HWND - A handle to the window
         *      Type: LPRECT - A pointer to a RECT structure that receives the screen coordinates of the upper-left and lower-right corners of the window.
         *      
         *      Return Value
         *      Type: BOOL - failed returns zero, succeeded returns nonzero
         */
        /// <summary>
        /// GetWindowRect() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd">a handle to the window</param>
        /// <param name="lpRect">a pointer to a RECT structure that receives the screen coordinates </param>
        /// <returns></returns>
        [DllImport("user32.dll", EntryPoint = "GetWindowRect", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, ref RECT lpRect);
        #endregion

        #region GetWindowText_done
        /*
         *      there is an public, an A and a W version of GetWindowText() function
         *      
         *      in case of problems with string interpretation try different CharSet
         *      
         *      Syntax
         *      int GetWindowTextA( HWND hWnd, LPSTR lpString, int nMaxCount );  <- Ansi
         *      int GetWindowTextW( HWND hWnd, LPWSTR lpString, int nMaxCount ); <- Unicode (should be choosen by CharSet.Unicode + ExactSpelling = false)
         *      int publicGetWindowText( HWND hWnd, LPWSTR pString, int cchMaxCount );
         *      
         *      Parameters
         *      Type: HWND - A handle to the window or control containing the text.
         *      Type: LPTSTR - The buffer that will receive the text. If the string is as long or longer than the buffer, 
         *                     the string is truncated and terminated with a null character.
         *      Type: int - The maximum number of characters to copy to the buffer, including the null character. 
         *                  If the text exceeds this limit, it is truncated.
         *      
         *      Return Value
         *      Type: int - If the function succeeds, the return value is the length, in characters, of the copied string, 
         *                  not including the terminating null character. If the window has no title bar or text, 
         *                  if the title bar is empty, or if the window or control handle is invalid, the return value is zero.
         *      
         */
        /// <summary>
        /// GetWindowText() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd"> A handle to the window or control containing the text. </param>
        /// <param name="lpString"> The buffer that will receive the text. </param>
        /// <param name="nMaxCount"> The maximum number of characters to copy to the buffer, including the null character. </param>
        /// <returns> return value is the length, empty title or invalid handle returns zero </returns>
        [DllImport("user32.dll", EntryPoint = "GetWindowText", CharSet = CharSet.Unicode, ExactSpelling = false, SetLastError = true)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        #endregion

        #region mouse_event_done
        /*
         *      Syntax
         *      void mouse_event( DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo );
         *      
         *      Parameters
         *      dwFlags - Type: DWORD - Controls various aspects of mouse motion and button clicking. This parameter can be certain combinations of the following values.
         *      dx - Type: DWORD - The mouse's absolute position along the x-axis or its amount of motion since the last mouse event was generated, depending on the setting of MOUSEEVENTF_ABSOLUTE. Absolute data is specified as the mouse's actual x-coordinate; relative data is specified as the number of mickeys moved. A mickey is the amount that a mouse has to move for it to report that it has moved.
         *      dy - Type: DWORD - The mouse's absolute position along the y-axis or its amount of motion since the last mouse event was generated, depending on the setting of MOUSEEVENTF_ABSOLUTE. Absolute data is specified as the mouse's actual y-coordinate; relative data is specified as the number of mickeys moved.
         *      dwData - Type: DWORD - If dwFlags contains MOUSEEVENTF_WHEEL, then dwData specifies the amount of wheel movement. A positive value indicates that the wheel was rotated forward, away from the user; a negative value indicates that the wheel was rotated backward, toward the user. One wheel click is defined as WHEEL_DELTA, which is 120.
         *                             If dwFlags contains MOUSEEVENTF_HWHEEL, then dwData specifies the amount of wheel movement. A positive value indicates that the wheel was tilted to the right; a negative value indicates that the wheel was tilted to the left.
         *                             If dwFlags contains MOUSEEVENTF_XDOWN or MOUSEEVENTF_XUP, then dwData specifies which X buttons were pressed or released. This value may be any combination of the following flags.
         *                             If dwFlags is not MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, or MOUSEEVENTF_XUP, then dwData should be zero.
         *      dwExtraInfo - Type: ULONG_PTR - An additional value associated with the mouse event. An application calls GetMessageExtraInfo to obtain this extra information.
         *      
         */
        /// <summary>
        ///  mouse_event() from winuser.h / user32.dll
        /// </summary>
        /// <param name="dwFlags"> Controls various aspects of mouse motion and button clicking. </param>
        /// <param name="dx"> The mouse's position along the x-axis </param>
        /// <param name="dy"> The mouse's position along the y-axis </param>
        /// <param name="dwData"> contains data about the action happend </param>
        /// <param name="dwExtraInfo"> An additional value associated with GetMessageExtraInfo </param>
        [DllImport("user32.dll", EntryPoint = "mouse_event")]
#pragma warning disable IDE1006 // Benennungsstile
        public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, UIntPtr dwExtraInfo);
#pragma warning restore IDE1006 // Benennungsstile
        // DWORD for dx and dy should be converted to unsigned 32 bit, 
        //       but since mouse can move relatively to last position it must be signed 32 bit
        #endregion

        #region MoveWindow_done
        /*      
         *      Syntax
         *      BOOL MoveWindow( HWND hWnd, int X, int Y, int nWidth, int nHeight, BOOL bRepaint );
         *      
         *      Parameters
         *      hWnd - Type: HWND - A handle to the window.
         *      X - Type: int - The new position of the left side of the window.
         *      Y - Type: int - The new position of the top of the window.
         *      nWidth - Type: int - The new width of the window.
         *      nHeight - Type: int - The new height of the window.
         *      bRepaint - Type: BOOL - Indicates whether the window is to be repainted. If this parameter is TRUE, 
         *                              the window receives a message. If the parameter is FALSE, no repainting of any kind occurs. 
         *                              This applies to the client area, the nonclient area (including the title bar and scroll bars), 
         *                              and any part of the parent window uncovered as a result of moving a child window.
         *      
         *      Return Value
         *      Type: BOOL - If the function succeeds, the return value is nonzero.
         *      
         */
        /// <summary>
        /// MoveWindow() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd"> A handle to the window </param>
        /// <param name="X"> The new position of the left side of the window </param>
        /// <param name="Y"> The new position of the top of the window </param>
        /// <param name="nWidth"> The new width of the window </param>
        /// <param name="nHeight"> The new height of the window </param>
        /// <param name="bRepaint"> Indicates whether the window is to be repainted </param>
        /// <returns> true if the function succeeds </returns>
        [DllImport("user32.dll", EntryPoint = "MoveWindow", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
        #endregion

        #region SetCursorPos_done 
        /*      
         *      Syntax
         *      BOOL SetCursorPos( int X, int Y );
         *      
         *      Parameters
         *      X - Type: int - The new x-coordinate of the cursor, in screen coordinates.
         *      Y - Type: int - The new y-coordinate of the cursor, in screen coordinates.
         *      
         *      Return Value
         *      Type: BOOL - Returns nonzero if successful or zero otherwise. 
         *      
         */
        /// <summary>
        /// SetCursorPos() from winuser.h / user32.dll
        /// </summary>
        /// <param name="X"> The new x-coordinate of the cursor, in screen coordinates </param>
        /// <param name="Y"> The new y-coordinate of the cursor, in screen coordinates </param>
        /// <returns> true if successful </returns>
        [DllImport("User32.Dll", EntryPoint = "SetCursorPos", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetCursorPos(int X, int Y);
        #endregion

        #region SetForegroundWindow_done
        /*
         *      Syntax
         *      BOOL SetForegroundWindow( HWND hWnd );
         *      
         *      Parameters
         *      hWnd - Type: HWND - A handle to the window that should be activated and brought to the foreground.
         *      
         *      Return Value
         *      Type: Type: BOOL - If the window was brought to the foreground, the return value is nonzero.
         *                         If the window was not brought to the foreground, the return value is zero.
         *                         
         */
        /// <summary>
        /// SetForegroundWindow() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd"> A handle to the window that should be activated and brought to the foreground </param>
        /// <returns> true if the window was brought to the foreground </returns>
        [DllImport("user32.dll", EntryPoint = "SetForegroundWindow", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
        #endregion

        #region SetFocus_done
        /*
         *      Syntax
         *      HWND SetFocus( HWND hWnd );
         *      
         *      Parameters
         *      hWnd - Type: HWND - A handle to the window that will receive the keyboard input. 
         *                          If this parameter is NULL, keystrokes are ignored.
         *      
         *      Return Value
         *      Type: HWND - If the function succeeds, the return value is the handle to the window that previously 
         *                   had the keyboard focus. If the hWnd parameter is invalid or the window is not attached 
         *                   to the calling thread's message queue, the return value is NULL.
         *                   
         */
        /// <summary>
        /// SetFocus() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd"> A handle to the window that will receive the keyboard input </param>
        /// <returns> if succeds, returns a handle to the window that previously had the keyboard focus or NULL </returns>
        [DllImport("user32.dll", EntryPoint = "SetFocus", SetLastError = true)]
        public static extern IntPtr SetFocus(IntPtr hWnd);
        #endregion

        #region ShowWindow_done
        /*
         *      Syntax
         *      BOOL ShowWindow( HWND hWnd, int nCmdShow );
         *      
         *      Parameters
         *      hWnd - Type: HWND - A handle to the window.
         *      nCmdShow - Type: int - Controls how the window is to be shown. 
         *                             This parameter is ignored the first time an application calls ShowWindow, 
         *                             if the program that launched the application provides a STARTUPINFO structure. 
         *                             Otherwise, the first time ShowWindow is called, the value should be the value 
         *                             obtained by the WinMain function in its nCmdShow parameter. 
         *                             In subsequent calls, this parameter can be one of the following values.
         *                             
         *      Return Value
         *      Type: Type: BOOL - If the window was previously visible, the return value is nonzero.
         *                         If the window was previously hidden, the return value is zero.
         *      
         */
        /// <summary>
        /// ShowWindow() from winuser.h / user32.dll
        /// </summary>
        /// <param name="hWnd"> A handle to the window </param>
        /// <param name="nCmdShow"> Controls how the window is to be shown </param>
        /// <returns> true if previously visible, false if previously hidden </returns>
        [DllImport("user32.dll", EntryPoint = "ShowWindow")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        #endregion

        #endregion

        #region Help_Structures

        #region WINDOWINFO_done
        /*      
         *      a struct for GetWindowInfo()
         *      
         *      typedef struct WINDOWINFO
         *      {
         *          DWORD cbSize;           //the size of the structure, in bytes
         *          RECT rcWindow;          //the coordinates of the window
         *          RECT rcClient;          //the coordinates of the client area
         *          DWORD dwStyle;          //the window styles
         *          DWORD dwExStyle;        //the extended window styles
         *          DWORD dwWindowStatus;   //The window status. If this member is WS_ACTIVECAPTION (0x0001), the window is active. Otherwise, this member is zero.
         *          UINT cxWindowBorders;   //The width of the window border, in pixels.
         *          UINT cyWindowBorders;   //The height of the window border, in pixels.
         *          ATOM atomWindowType;    //The window class atom (see RegisterClass).
         *          WORD wCreatorVersion;   //The Windows version of the application that created the window.
         *      }
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct WINDOWINFO
        {
            public uint cbSize;
            [MarshalAs(UnmanagedType.LPStruct)]
            public RECT rcWindow;
            [MarshalAs(UnmanagedType.LPStruct)]
            public RECT rcClient;
            public uint dwStyle;
            public uint dwExStyle;
            public uint dwWindowStatus;
            public uint cxWindowBorders;
            public uint cyWindowBorders;
            //public ATOM atomWindowType;       // external register class (16 bit - WORD)
            [MarshalAs(UnmanagedType.U2)]
            public ushort atomWindowType;
            public ushort wCreatorVersion;
        }
        #endregion

        #region RECT_done
        /*      
         *      a struct for GetWindowInfo().WINDOWINFO
         *      a struct for GetWindowRect()
         *      
         *      typedef struct RECT
         *      {
         *          LONG left;      // x position of upper-left corner 
         *          LONG top;       // y position of upper-left corner 
         *          LONG right;     // x position of lower-right corner 
         *          LONG bottom;    // y position of lower-right corner
         *      }
         */
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
        #endregion

        #region mouse_event_dwFlags_done
        /*
         *      Flags for dwFlags in mouse_event()
         */
        public struct DwFlags
        {
            public static uint MOUSEEVENTF_ABSOLUTE = 0x8000;     //The dx and dy parameters contain normalized absolute coordinates.If not set, those parameters contain relative data: the change in position since the last reported position.This flag can be set, or not set, regardless of what kind of mouse or mouse-like device, if any, is connected to the system. For further information about relative mouse motion, see the following Remarks section.
            public static uint MOUSEEVENTF_LEFTDOWN = 0x0002;     //The left button is down.
            public static uint MOUSEEVENTF_LEFTUP = 0x0004;       //The left button is up.
            public static uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;   //The middle button is down.
            public static uint MOUSEEVENTF_MIDDLEUP = 0x0040;     //The middle button is up.
            public static uint MOUSEEVENTF_MOVE = 0x0001;         //Movement occurred.
            public static uint MOUSEEVENTF_RIGHTDOWN = 0x0008;    //The right button is down.
            public static uint MOUSEEVENTF_RIGHTUP = 0x0010;      //The right button is up.
            public static uint MOUSEEVENTF_WHEEL = 0x0800;        //The wheel has been moved, if the mouse has a wheel.The amount of movement is specified in dwData
            public static uint MOUSEEVENTF_XDOWN = 0x0080;        //An X button was pressed.
            public static uint MOUSEEVENTF_XUP = 0x0100;          //An X button was released.
                                                                  //double    public static uint MOUSEEVENTF_WHEEL = 0x0800;        //The wheel button is rotated.
            public static uint MOUSEEVENTF_HWHEEL = 0x01000;      //The wheel button is tilted. 
        }
        #endregion

        #region mouse_event_dwData_Flags_done
        /*
         *      Flags for dwData in mouse_event()
         */
        public struct DwDataFlags
        {
            public static uint WHEEL_DELTA = 120;     //One wheel click is defined as WHEEL_DELTA, which is 120.
            public static uint XBUTTON1 = 0x0001;     //Set if the first X button was pressed or released.
            public static uint XBUTTON2 = 0x0002;     //Set if the second X button was pressed or released. 
        }
        #endregion

        #region ShowWindow_nCmdShow_Flags_done
        /*
         *      Flags for nCmdShow in ShowWindow()
         */
        public struct NCmdShowFlags
        {
            public static int SW_FORCEMINIMIZE = 11;      //Minimizes a window, even if the thread that owns the window is not responding.This flag should only be used when minimizing windows from a different thread.
            public static int SW_HIDE = 0;                //Hides the window and activates another window.
            public static int SW_MAXIMIZE = 3;            //Maximizes the specified window.
            public static int SW_MINIMIZE = 6;            //Minimizes the specified window and activates the next top-level window in the Z order.
            public static int SW_RESTORE = 9;             //Activates and displays the window.If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when restoring a minimized window.
            public static int SW_SHOW = 5;                //Activates the window and displays it in its current size and position.
            public static int SW_SHOWDEFAULT = 10;        //Sets the show state based on the SW_ value specified in the STARTUPINFO structure passed to the CreateProcess function by the program that started the application.
            public static int SW_SHOWMAXIMIZED = 3;       //Activates the window and displays it as a maximized window.
            public static int SW_SHOWMINIMIZED = 2;       //Activates the window and displays it as a minimized window.
            public static int SW_SHOWMINNOACTIVE = 7;     //Displays the window as a minimized window.This value is similar to SW_SHOWMINIMIZED, except the window is not activated.
            public static int SW_SHOWNA = 8;              //Displays the window in its current size and position.This value is similar to SW_SHOW, except that the window is not activated.
            public static int SW_SHOWNOACTIVATE = 4;      //Displays a window in its most recent size and position. This value is similar to SW_SHOWNORMAL, except that the window is not activated.
            public static int SW_SHOWNORMAL = 1;          //Activates and displays a window.If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
        }
        #endregion




        #region WM Flags
        /*      Flags for keyboard and mouse
         */
        public struct WM_Flags
        {
            public static uint WM_ACTIVATE = 0x0006;
            public static uint WM_SETFOCUS = 0x0007;
            public static uint WM_SETCURSOR = 0x0020;
            public static uint WM_NCLBUTTONDOWN = 0x00A1;
            public static uint WM_NCLBUTTONUP = 0x00A2;
            public static uint WM_NCRBUTTONDOWN = 0x00A4;
            public static uint WM_NCRBUTTONUP = 0x00A5;
            public static uint WM_NCHITTEST = 0x0084;
            public static uint WM_KEYDOWN = 0x0100;
            public static uint WM_KEYUP = 0x0101;
            public static uint WM_CHAR = 0x0102;
            public static uint WM_MOUSEMOVE = 0x0200;
            public static uint WM_LBUTTONDOWN = 0x0201;
            public static uint WM_LBUTTONUP = 0x0202;
            public static uint WM_RBUTTONDOWN = 0x0204;
            public static uint WM_RBUTTONUP = 0x0205;



            #region Virtual Key Codes
            public static uint VK_LBUTTON = 0x01; //	            Left mouse button
            public static uint VK_RBUTTON = 0x02; //                Right mouse button
            public static uint VK_CANCEL = 0x03; //                 Control-break processing
            public static uint VK_MBUTTON = 0x04; //                Middle mouse button(three-button mouse)
            public static uint VK_XBUTTON1 = 0x05; //               X1 mouse button
            public static uint VK_XBUTTON2 = 0x06; //               X2 mouse button
            public static uint VK_BACK = 0x08; //                   BACKSPACE key
            public static uint VK_TAB = 0x09; //                	TAB key
            public static uint VK_CLEAR = 0x0C; //                  CLEAR key
            public static uint VK_RETURN = 0x0D; //                 ENTER key
            public static uint VK_SHIFT = 0x10; //                  SHIFT key
            public static uint VK_CONTROL = 0x11;//                	CTRL key
            public static uint VK_MENU = 0x12;//                    ALT key
            public static uint VK_PAUSE = 0x13;//               	PAUSE key
            public static uint VK_CAPITAL = 0x14;//                	CAPS LOCK key
            public static uint VK_ESCAPE = 0x1B;//                  ESC key
            public static uint VK_CONVERT = 0x1C;//               	IME convert
            public static uint VK_NONCONVERT = 0x1D;//            	IME nonconvert
            public static uint VK_ACCEPT = 0x1E;//           	    IME accept
            public static uint VK_MODECHANGE = 0x1F;//            	IME mode change request
            public static uint VK_SPACE = 0x20;//               	SPACEBAR
            public static uint VK_PRIOR = 0x21;//                   PAGE UP key
            public static uint VK_NEXT = 0x22;//                    PAGE DOWN key
            public static uint VK_END = 0x23;//                     END key
            public static uint VK_HOME = 0x24;//                	HOME key
            public static uint VK_LEFT = 0x25;//                	LEFT ARROW key
            public static uint VK_UP = 0x26;//                      UP ARROW key
            public static uint VK_RIGHT = 0x27;//                   RIGHT ARROW key
            public static uint VK_DOWN = 0x28;//                    DOWN ARROW key
            public static uint VK_SELECT = 0x29;//                  SELECT key
            public static uint VK_PRINT = 0x2A;//            	    PRINT key
            public static uint VK_EXECUTE = 0x2B;//            	    EXECUTE key
            public static uint VK_SNAPSHOT = 0x2C;//            	PRINT SCREEN key
            public static uint VK_INSERT = 0x2D;//                  INS key
            public static uint VK_DELETE = 0x2E;//              	DEL key
            public static uint VK_HELP = 0x2F;//                	HELP key
            public const uint VK_0 = 0x30;//                0 key
            public const uint VK_1 = 0x31;//           	    1 key
            public const uint VK_2 = 0x32;//           	    2 key
            public const uint VK_3 = 0x33;//            	3 key
            public const uint VK_4 = 0x34;//            	4 key
            public const uint VK_5 = 0x35;//            	5 key
            public const uint VK_6 = 0x36;//            	6 key
            public const uint VK_7 = 0x37;//            	7 key
            public const uint VK_8 = 0x38;//            	8 key
            public const uint VK_9 = 0x39;//            	9 key
            public const uint VK_A = 0x41;//            	A key
            public const uint VK_B = 0x42;//                B key
            public const uint VK_C = 0x43;//                C key
            public const uint VK_D = 0x44;//                D key
            public const uint VK_E = 0x45;//                E key
            public const uint VK_F = 0x46;//                F key
            public const uint VK_G = 0x47;//                G key
            public const uint VK_H = 0x48;//                H key
            public const uint VK_I = 0x49;//                I key
            public const uint VK_J = 0x4A;//                J key
            public const uint VK_K = 0x4B;//                K key
            public const uint VK_L = 0x4C;//                L key
            public const uint VK_M = 0x4D;//                M key
            public const uint VK_N = 0x4E;//                N key
            public const uint VK_O = 0x4F;//                O key
            public const uint VK_P = 0x50;//                P key
            public const uint VK_Q = 0x51;//                Q key
            public const uint VK_R = 0x52;//                R key
            public const uint VK_S = 0x53;//                S key
            public const uint VK_T = 0x54;//                T key
            public const uint VK_U = 0x55;//                U key
            public const uint VK_V = 0x56;//                V key
            public const uint VK_W = 0x57;//                W key
            public const uint VK_X = 0x58;//                X key
            public const uint VK_Y = 0x59;//                Y key
            public const uint VK_Z = 0x5A;//                Z key
            public const uint VK_LWIN = 0x5B;//            	Left Windows key(Natural keyboard)
            public const uint VK_RWIN = 0x5C;//            	Right Windows key(Natural keyboard)
            public const uint VK_APPS = 0x5D;//            	Applications key(Natural keyboard)
            public const uint VK_SLEEP = 0x5F;//            Computer Sleep key
            public const uint VK_NUMPAD0 = 0x60;//                Numeric keypad 0 key
            public const uint VK_NUMPAD1 = 0x61;//                Numeric keypad 1 key
            public const uint VK_NUMPAD2 = 0x62;//                Numeric keypad 2 key
            public const uint VK_NUMPAD3 = 0x63;//                Numeric keypad 3 key
            public const uint VK_NUMPAD4 = 0x64;//                Numeric keypad 4 key
            public const uint VK_NUMPAD5 = 0x65;//                Numeric keypad 5 key
            public const uint VK_NUMPAD6 = 0x66;//                Numeric keypad 6 key
            public const uint VK_NUMPAD7 = 0x67;//                Numeric keypad 7 key
            public const uint VK_NUMPAD8 = 0x68;//                Numeric keypad 8 key
            public const uint VK_NUMPAD9 = 0x69;//                Numeric keypad 9 key
            public const uint VK_MULTIPLY = 0x6A;//               Multiply key
            public const uint VK_ADD = 0x6B;//            	      Add key
            public const uint VK_SEPARATOR = 0x6C;//           	  Separator key
            public const uint VK_SUBTRACT = 0x6D;//            	  Subtract key
            public const uint VK_DECIMAL = 0x6E;//            	  Decimal key
            public const uint VK_DIVIDE = 0x6F;//            	  Divide key
            public const uint VK_F1 = 0x70;//            	F1 key
            public const uint VK_F2 = 0x71;//            	F2 key
            public const uint VK_F3 = 0x72;//            	F3 key
            public const uint VK_F4 = 0x73;//           	F4 key
            public const uint VK_F5 = 0x74;//            	F5 key
            public const uint VK_F6 = 0x75;//            	F6 key
            public const uint VK_F7 = 0x76;//            	F7 key
            public const uint VK_F8 = 0x77;//           	F8 key
            public const uint VK_F9 = 0x78;//            	F9 key
            public const uint VK_F10 = 0x79;//            	F10 key
            public const uint VK_F11 = 0x7A;//            	F11 key
            public const uint VK_F12 = 0x7B;//            	F12 key
            public const uint VK_NUMLOCK = 0x90;             //     NUM LOCK key
            public const uint VK_SCROLL = 0x91;//                   SCROLL LOCK key
            public const uint VK_LSHIFT = 0xA0;//                   Left SHIFT key
            public const uint VK_RSHIFT = 0xA1;//                   Right SHIFT key
            public const uint VK_LCONTROL = 0xA2;//                 Left CONTROL key
            public const uint VK_RCONTROL = 0xA3;//                 Right CONTROL key
            public const uint VK_LMENU = 0xA4;//                    Left MENU key
            public const uint VK_RMENU = 0xA5;//                    Right MENU key
            public const uint VK_BROWSER_BACK = 0xA6;//                   Browser Back key
            public const uint VK_BROWSER_FORWARD = 0xA7;//                Browser Forward key
            public const uint VK_BROWSER_REFRESH = 0xA8;//                Browser Refresh key
            public const uint VK_BROWSER_STOP = 0xA9;//                   Browser Stop key
            public const uint VK_BROWSER_SEARCH = 0xAA;//                 Browser Search key
            public const uint VK_BROWSER_FAVORITES = 0xAB;//              Browser Favorites key
            public const uint VK_BROWSER_HOME = 0xAC;//                   Browser Start and Home key
            public const uint VK_VOLUME_MUTE = 0xAD;//                    Volume Mute key
            public const uint VK_VOLUME_DOWN = 0xAE;//                    Volume Down key
            public const uint VK_VOLUME_UP = 0xAF;//                      Volume Up key
            public const uint VK_MEDIA_NEXT_TRACK = 0xB0;//               Next Track key
            public const uint VK_MEDIA_PREV_TRACK = 0xB1;//               Previous Track key
            public const uint VK_MEDIA_STOP = 0xB2;//                     Stop Media key
            public const uint VK_MEDIA_PLAY_PAUSE = 0xB3;//               Play/Pause Media key
            public const uint VK_LAUNCH_MAIL = 0xB4;//                    Start Mail key
            public const uint VK_LAUNCH_MEDIA_SELECT = 0xB5;//            Select Media key
            public const uint VK_LAUNCH_APP1 = 0xB6;//                    Start Application 1 key
            public const uint VK_LAUNCH_APP2 = 0xB7;//                    Start Application 2 key
            public const uint VK_OEM_1 = 0xBA;//                          For the US standard keyboard, the ';:' key
            public const uint VK_OEM_PLUS = 0xBB;//                       For any country/region, the '+' key
            public const uint VK_OEM_COMMA = 0xBC;//                      For any country/region, the ',' key
            public const uint VK_OEM_MINUS = 0xBD;//                      For any country/region, the '-' key
            public const uint VK_OEM_PERIOD = 0xBE;//                     For any country/region, the '.' key
            public const uint VK_OEM_2 = 0xBF;//                          For the US standard keyboard, the '/?' key
            public const uint VK_OEM_3 = 0xC0;//                          For the US standard keyboard, the '`~' key
            public const uint VK_OEM_4 = 0xDB;//                          For the US standard keyboard, the '[{' key
            public const uint VK_OEM_5 = 0xDC;//                          For the US standard keyboard, the '\|' key
            public const uint VK_OEM_6 = 0xDD;//                          For the US standard keyboard, the ']}' key
            public const uint VK_OEM_7 = 0xDE;//                          For the US standard keyboard, the 'single-quote/double-quote' key
            public const uint VK_OEM_8 = 0xDF;//                          Used for miscellaneous characters; it can vary by keyboard.
            public const uint VK_OEM_102 = 0xE2;//            	          Either the angle bracket key or the backslash key on the RT 102-key keyboard
            public const uint VK_PROCESSKEY = 0xE5;//                     IME PROCESS key
            public const uint VK_PACKETpublic = 0xE7;//                   Used to pass Unicode characters as if they were keystrokes.The VK_PACKET key is the low word of a 32-bit Virtual Key value used for non-keyboard input methods.For more information, see Remark in KEYBDINPUT, SendInput, WM_KEYDOWN, and WM_KEYUP
            public const uint VK_ATTN = 0xF6;//                 Attn key
            public const uint VK_CRSEL = 0xF7;//            	CrSel key
            public const uint VK_EXSEL = 0xF8;//            	ExSel key
            public const uint VK_EREOF = 0xF9;//          	    Erase EOF key
            public const uint VK_PLAY = 0xFA;//                 Play key
            public const uint VK_ZOOM = 0xFB;//            	    Zoom key
            public const uint VK_NONAME = 0xFC;//            	Reserved
            public const uint VK_PA1 = 0xFD;//                  PA1 key
            public const uint VK_OEM_CLEAR = 0xFE;//            Clear key
            #endregion
        }
        #endregion



        #endregion

        #region imports for WindowDictionary
        public delegate bool EnumWindowsProc(IntPtr hWnd, int lParam);

        [DllImport("USER32.DLL")]
        public static extern bool EnumWindows(EnumWindowsProc enumFunc, int lParam);

        //[DllImport("USER32.DLL")]
        //public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("USER32.DLL")]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("USER32.DLL")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("USER32.DLL")]
        public static extern IntPtr GetShellWindow();

        [DllImport("USER32.DLL", EntryPoint = "GetCursorPos")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetCursorPos(ref Point lpPoint);

        #endregion

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessage(IntPtr hWnd, uint msg, uint wParam, uint lParam);

        // arsch
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SendMessage(IntPtr hWnd, uint msg, uint wParam, uint lParam);

        [DllImport("user32.dll")]
        public static extern bool ScreenToClient(IntPtr hWnd, ref Point lpPoint);

        [DllImport("user32.dll")]
        public static extern IntPtr SetCapture(IntPtr hWnd);

    }

}
