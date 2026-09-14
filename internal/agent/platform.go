package agent

// Windows DACLs for the data dir and the files in it: protected (nothing
// inherited from C:\ProgramData), full control for LocalSystem (SY) and
// BUILTIN\Administrators (BA), no other entries. The directory's entries
// are inherited by everything created inside it (OICI).
const (
	dirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)
