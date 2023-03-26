/*
==================================================================================================================================================================================================================
==================================================================================================================================================================================================================
=================================   UTILS   ======================================================================================================================================================================
==================================================================================================================================================================================================================
==================================================================================================================================================================================================================
*/
function generateStr(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
      counter += 1;
    }
    return result;
}

/*
==================================================================================================================================================================================================================
==================================================================================================================================================================================================================
=================================   HOOKS  =======================================================================================================================================================================
==================================================================================================================================================================================================================
==================================================================================================================================================================================================================
*/


/*
BOOL CreateProcessA(
 0 [in, optional]      LPCSTR                lpApplicationName,
 1 [in, out, optional] LPSTR                 lpCommandLine,
 2 [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
 3 [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
 4 [in]                BOOL                  bInheritHandles,
 5 [in]                DWORD                 dwCreationFlags,
 6 [in, optional]      LPVOID                lpEnvironment,
 7 [in, optional]      LPCSTR                lpCurrentDirectory,
 8 [in]                LPSTARTUPINFOA        lpStartupInfo,
 9 [out]               LPPROCESS_INFORMATION lpProcessInformation
);
*/

let pCreateProcessA = Module.findExportByName("KERNEL32.dll", "CreateProcessA");
Interceptor.attach(pCreateProcessA, {
	onEnter: function(args) {
		this.application = args[0].readUtf8String();
		this.commandline = args[1].readUtf8String();
		this.procinfo	 = args[9];
		args[4]			 = new NativePointer(0x4); // Always create suspended.
		if (this.application == null) {
			this.application = "cmd.exe";
		}
	},
	onLeave: function(retval) {
		send( {
		'Notified':'PostExec',
		'Function':'CreateProcessA',
		'Application': this.application,
		'CommandLine':this.commandline,
		'PID':this.procinfo.add(2 * Process.pointerSize).readPointer().toInt32(),
		'ret':retval.toInt32()
		} );
	}
});

/*
BOOL IsDebuggerPresent();
*/
let pIsDebuggerPresent = Module.findExportByName(null, "IsDebuggerPresent");
Interceptor.attach(pIsDebuggerPresent, {
	onLeave: function(retval) {
		retval.replace(1);
		send( {
		'Notified':'PostExec',
		'Function':'IsDebuggerPresent',
		} );
	}
});

/*
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
*/
let pWriteProcessMemory = Module.findExportByName(null, "WriteProcessMemory");
Interceptor.attach(pWriteProcessMemory, {
	onEnter: function(args) {
		const signature = args[2].readU16();
		this.baseaddr = args[1].toInt32();
		this.buffersize = args[3].toInt32();
		this.buffaddr = args[2].toInt32();
		if (signature == 23117) {
			send({
			'Notified':'PreExec',
			'Function':'WriteProcessMemory',
			'base':this.baseaddr,
			'buffer addr': this.buffaddr,
			'size':this.buffersize,
			'sig':signature
			}, args[2].readByteArray(this.buffersize));
		} else {
			send({
				'Notified':'PreExec',
				'Function':'WriteProcessMemory',
				'base':this.baseaddr,
				'buffer addr': this.buffaddr,
				'size':this.buffersize,
				'sig':signature
				});
		}
	}
});

/*
DWORD ResumeThread(
  [in] HANDLE hThread
);
*/

let pResumeThread = Module.findExportByName(null, "ResumeThread");
Interceptor.attach(pResumeThread, {
	onEnter: function(args) {
		args[0] = new NativePointer(0);
		send({
		'Notified':'PreExec',
		'Function': 'ResumeThread',
		'Arg': 'Squashed',
		'Action': 'Kill now'
		});
		recv();
	}
});
