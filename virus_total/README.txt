

                            Virus Total Scan Report
                            -----------------------
                            
[ intro

Using Win HTTP API functions, this tool queries Virus Total website for scan
reports. It's very basic functionality and only useful to anyone interested
in queries using C/C++.

The hashing algorithms are MD5, SHA-1 and SHA-256 (default)
You can use switches to change algorithms (/md5, /sha1, /sha2)

It was written for integration with another tool but I thought it
might prove useful to others. Here's an example of scanning SQL
slammer virus.

  [ checking HELKERN.000
41 virus scanner results
  [ detected by McAfee+Artemis       : W32/SQLSlammer.worm
  [ detected by McAfee               : W32/SQLSlammer.worm
  [ detected by TheHacker            : W32/SQLSlammer
  [ detected by VirusBuster          : Win32.SQLExp.A
  [ detected by a-squared            : Worm.Sql.Slammer.dmp!IK
  [ detected by Avast                : Win32:SQLSlammer
  [ detected by BitDefender          : Worm.Sql.Slammer.Dump.A
  [ detected by Comodo               : Worm.Win32.SQLSlammer.~A
  [ detected by DrWeb                : Win32.SQL.Slammer.368
  [ detected by AntiVir              : Worm/Sql.Slammer.dmp
  [ detected by McAfee-GW-Edition    : Heuristic.BehavesLike.Exploit.CodeExec.FFLG
  [ detected by eTrust-Vet           : Win32/SQLSlammer
  [ detected by Antiy-AVL            : Worm/Win32.Slammer
  [ detected by Symantec             : W32.SQLExp.Worm.dump
  [ detected by Microsoft            : Worm:Win32/SQLSlammer.remnants
  [ detected by GData                : Worm.Sql.Slammer.Dump.A
  [ detected by PCTools              : Win32.SQLExp.A
  [ detected by Ikarus               : Worm.Sql.Slammer.dmp
  [ detected by Fortinet             : W32/SQLSlammer!worm
  [ detected by AVG                  : SQLSlammer
  [ detected by Panda                : Worm Generic
  
  
[ compile

  cl vt.cpp md5.c sha1.c sha256.c jsmn.c wsetargv.obj

[ todo

add /upload option

