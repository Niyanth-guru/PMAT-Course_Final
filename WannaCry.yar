rule WannaCry_catcher {
    meta:
        author = "Niyanth Guruprasad"
        Created on = "08-10-2024"
        Last updated on = "08-10-2024"
        Description = "Detection Rule for WannaCry Ransomware,PMAT"
    
    strings:
        $PE_magic_header_byte = "MZ" 
        $External_URL = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $hidden_directory = "C:\ProgramData\%s"
        $spawned_executables1 = "tasksche.exe"
        $spawned_executbales2 = "taskse.exe"
        $spawned_executables3 = "taskdl.exe"
        $common_file_extension = ".wnry"

    condition:
        $PE_magic_header_byte at 0 and $common_file_extension and $External_URL and $hidden_directory and ($spawned_executables1 or $spawned_executables2 or $spawned_executables3)
}