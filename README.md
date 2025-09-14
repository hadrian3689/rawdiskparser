# Raw Disk Parser
Inspired by https://medium.com/workday-engineering/leveraging-raw-disk-reads-to-bypass-edr-f145838b0e6d, where the POC was written in Python. Decided to write in GO, with help from GPT, so that we can cross-compile.

## Compiling
```
GOOS=windows GOARCH=amd64 go build -o rawdiskparser.exe rawdiskparser.go
```

## Decrypting
```
python3 simple_xor.py <encrypted_file> <output_file>
```

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.
