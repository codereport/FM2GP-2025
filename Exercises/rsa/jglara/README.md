# From Mathematics to Generic Programming

## RSA project

To generate public and private keys:

```
rsa_keygen [OPTIONS] --pubkey <PUBKEY> --prvkey <PRVKEY>

Options:
  -k, --key-size <KEY_SIZE>  [default: 64]
      --pubkey <PUBKEY>      
      --prvkey <PRVKEY>      
```

prvkey and pubkey are filenames to store n and key in json format

Then you can use this command to encrypt a file input to output using key

```
rsa_encrypt --key <KEY> --input <INPUT> --output <OUTPUT>

Options:
  -k, --key <KEY>        
  -i, --input <INPUT>    
  -o, --output <OUTPUT>  
```

And you can decrypt with: 

```
rsa_decrypt --key <KEY> --input <INPUT> --output <OUTPUT>

Options:
  -k, --key <KEY>        
  -i, --input <INPUT>    
  -o, --output <OUTPUT>  
```
