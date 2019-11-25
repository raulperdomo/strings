#!/usr/bin/python3
import sys, getopt, subprocess, re, pprint, json
import vt

def help():
    print("This tool is designed to gather useful information from compiled binary files."
          "\n\nThe default usage is:\n\tstrings.py [options] path_to_file\n\n"
          "Flags can be set to specify certain types of data.\n\nOptions:"
          "\n\t-o filename -- this option specifies a file to write the output to, instead of stdout. Unlike stdout, this option does not add tabs before strings."
          "\n\t-u -- parse URLs"
          "\n\t-d -- parse DLLs"
          "\n\t-i -- parse IP Addresses"
          "\n\t-p -- parse File Paths"
          "\n\t-k -- parse Registry Keys"
          "\n\t-f -- parse Files"
          "\n\t-h -- parse SHA1 hash"
          "\n\t-v -- checks the SHA1sum value against VirusTotal's database and prints the report. If -o is selected this information is saved in a second file VirusTotalReport-filename."
          )
    sys.exit()
    
def stdout(SHA1sum, DLLs, PATHs, IPs, URLs, Keys, Files, UNCAT, opts):
    
    if SHA1sum:
        print('\nSHA1 Hash:')
        print("\t",SHA1sum,'\n')
    
    if DLLs:         
        print("DLLs Found:")
        [print("\t",d) for d in DLLs]
        
    if PATHs:
        print("\nPaths Found:")
        [print("\t",d) for d in PATHs]
        
    if IPs:
        print("\nIPs Found:")
        [print("\t", i) for i in IPs]
        
    if URLs:
        print("\nURLs Found:")
        [print("\t", u) for u in URLs]
            
    if Keys:
        print("\nRegistry Keys Found:")
        [print("\t", k) for k in Keys]
        
    if Files:
        print("\nFiles Found:")
        [print("\t",f) for f in Files]
    
    yn = input("Would you like to see uncategorized strings? (y/N) ")
    
    if 'Y' in yn.upper():
        [print("\t",u) for u in UNCAT]
    
    if '-v' in opts:
        print("\nVirusTotal report:\n")
        pprint.pprint(vt.VTreport(SHA1sum))

def writeFile(SHA1sum, DLLs, PATHs, IPs, URLs, Keys, Files, UNCAT, opts):
    yn = input("Would you like to write uncategorized strings? (y/N) ")
    try:    
        with open(opts['-o'], 'w') as f:
            
            if SHA1sum:
                f.write('\nSHA1 Hash:')
                f.write("\n" + SHA1sum +'\n')
            
            if DLLs:         
                f.write("\n\nDLLs Found:")
                [f.write("\n" + d) for d in DLLs]
                
            if PATHs:
                f.write("\n\nPaths Found:")
                [f.write("\n" + d) for d in PATHs]
                
            if IPs:
                f.write("\n\nIPs Found:")
                [f.write("\n" + i) for i in IPs]
                
            if URLs:
                f.write("\n\nURLs Found:")
                [f.write("\n" + u) for u in URLs]
                    
            if Keys:
                f.write("\n\nRegistry Keys Found:")
                [f.write("\n" + k) for k in Keys]
                
            if Files:
                f.write("\n\nFiles Found:")
                [f.write("\n" + f) for f in Files]
            
            if 'Y' in yn.upper():
                f.write("\n\nUncategorized Strings:")
                [f.write("\n" + u) for u in UNCAT]
                
        if '-v' in opts:
            with open(f"VirusTotalReport-{opts['-o']}", 'w') as v:
                json.dump(vt.VTreport(SHA1sum), v)    
                
    except Exception as e:
        print("Error writing to file.")
        print(e)
        sys.exit()
           
def getOpts():
    opts, args = getopt.getopt(sys.argv[1:], "udipkfhvo:",['help'])
    opts = dict(opts)
    optionsSelected = []
    for o in opts:
        optionsSelected.append(o[1])

    if '--help' in opts:
        help()

    selectedCount = 0
    for o in optionsSelected:
        if o in "udipkfh":
            selectedCount += 1
            
    if selectedCount == 0:
        opts['-u'] = ''
        opts['-d'] = ''
        opts['-i'] = ''
        opts['-p'] = ''
        opts['-k'] = ''
        opts['-f'] = ''
        opts['-h'] = ''

        
    return (opts, args)
    
def main(): 
    opts, args = getOpts()
    print(f"Analyzing File: {args[0]}".center(80, '-'))
    
    SHA1sum = None
    if '-h' in opts:
        try:
            SHA1 = subprocess.run(f"sha1sum {args[0]}", shell=True, capture_output=True)
            SHA1sum = SHA1.stdout.strip().decode("utf-8").split()[0]
            
        except Exception as e:
            print(e)

    try:
        stringsCall = subprocess.run(f"strings {args[0]}", shell=1, capture_output=1)
    except:
        print(stringsCall.returncode)
    else:
        
        DLL = re.compile(".*\.DLL.*", re.I)
        URL = re.compile("((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*")
        IP = re.compile(".*(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).*")
        REG = re.compile('.*(HKEY_LOCAL_MACHINE|HKLM|hkey_local_machine)\\\\([a-zA-Z0-9\s_@\-\^!#.\:\/\$%&+={}\[\]\\\\*])+$')
        FILENAMES = re.compile(".*\.(EXE|TXT|JPG|JPEG|GIF|DOC|DOCX|XLS|XLSX|CSV|PPT|PPTX|LNK|PDF|RTF|MP3|MPG|MPEG|MOV|MP4|CPP|PY).*", re.I)
        PATH = re.compile("[A-Z]:\\\\",re.I)
        IPs = []
        URLs = []
        KEYs = []
        FILEs = []
        DLLs = []
        PATHs = []
        UNCAT = []
        strings = stringsCall.stdout.decode("utf-8").split('\n')
        for string in strings:
            
            if re.match(PATH,string.strip()) and '-p' in opts:
                PATHs.append(string)
            elif re.match(DLL, string.strip()) and '-d' in opts:
                DLLs.append(string)
            elif re.match(FILENAMES, string.strip()) and '-f' in opts:
                FILEs.append(string)
            elif re.match(URL, string.strip()) and '-u' in opts:
                URLs.append(string)
            elif re.match(IP, string.strip()) and '-i' in opts:
                IPs.append(string)
            elif re.match(REG, string.strip()) and '-k' in opts:
                KEYs.append(string)
            else:
                UNCAT.append(string)

        if '-o' not in opts:
            stdout(SHA1sum, DLLs, PATHs, IPs, URLs, KEYs, FILEs, UNCAT, opts)
        else:
            print("Saving results to file...")
            writeFile(SHA1sum, DLLs, PATHs, IPs, URLs, KEYs, FILEs, UNCAT, opts)
            
                


if __name__ == "__main__":
    main()