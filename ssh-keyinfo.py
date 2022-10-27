import base64
import sys
import os

def main():
    if len(sys.argv)<2:
        print_usage()
        return
    
    for keyfile in sys.argv[1:]:
        print()
        if not os.path.exists(keyfile):
            print(f"No such file: {keyfile}")
            continue
            
        print(f"{keyfile}:")
        
        # Extract base64 data
        did_begin = False
        base64_data = b""
        with open(keyfile,'rb') as keyfile:
            for line in keyfile:
                if b'---' in line and b'BEGIN' in line:
                    did_begin = True
                elif b'---' in line and b'END' in line:
                    break
                elif did_begin:
                    base64_data += line
        
        if len(base64_data) == 0:
            print(f"  No key data found. Is the file a private key with --- BEGIN and --- END markers?")
            continue
        
        keybuffer = BinaryBuffer(base64.b64decode(base64_data))
        
        print(f"  length = {len(keybuffer.data)} bytes")
        
        
        # Check for OpenSSH Auth Magic
        try:
            auth_magic = b"openssh-key-v1\0"
            magic = keybuffer.read_fixed_string(len(auth_magic))
            is_openssh = magic == auth_magic
        except:
            is_openssh = False
        
        if is_openssh:
            # open SSH keyfile
            print(f"  Key File Format: OpenSSH Key File Format Version 1")
            
            try:
                ciphername = keybuffer.read_var_string().decode()
                print(f"  ciphername: {ciphername}")

                kdfname = keybuffer.read_var_string().decode()
                print(f"  kdfname: {kdfname}")

                kdfoptions = keybuffer.read_var_string()
                print(f"  kdfoptions: {kdfoptions}")
                
                num_keys = keybuffer.read_uint32()
                print(f"  number of keys: {num_keys}")
                
                for i in range(1,num_keys+1):
                    pubkey = keybuffer.read_var_string()
                    print(f"  public key {i}:")
                    pubkey = BinaryBuffer(pubkey)
                    pubkey_type = pubkey.read_var_string().decode()
                    print(f"    type: {pubkey_type}")
                    pubkey_bytes = pubkey.read_var_string()
                    print(f"    data: {base64.b64encode(pubkey_bytes).decode()}")
                    
                
                private_key_data = keybuffer.read_var_string()
                if ciphername != "none":
                    print(f"  private key data: {len(private_key_data)} bytes (encrypted)")
                else:
                    privbuffer = BinaryBuffer(private_key_data)
                    
                    checkint1 = privbuffer.read_uint32()
                    checkint2 = privbuffer.read_uint32()
                    print(f"  checkints: {checkint1}{'==' if checkint1==checkint2 else '!='}{checkint2}")
                    
                    for i in range(1,num_keys+1):
                        print(f"  private key {i}:")
                        key_type = privbuffer.read_var_string().decode()
                        print(f"    type: {key_type}")
                        
                        if key_type == "ssh-dss":
                            p = privbuffer.read_mpint()
                            q = privbuffer.read_mpint()
                            g = privbuffer.read_mpint()
                            y = privbuffer.read_mpint()
                            x = privbuffer.read_mpint()
                            print("    Parameters:")
                            print(f"      p = {p}")
                            print(f"      q = {q}")
                            print(f"      g = {g}")
                            print(f"      y = {y}")
                            print(f"      x = {x}")
                        elif 'ecdsa-sha2-' in key_type:
                            print("    Parameters:")
                            ecdsa_curve_name = privbuffer.read_var_string().decode()
                            print(f"      ecdsa_curve_name = {ecdsa_curve_name}")
                            Q = privbuffer.read_var_string()
                            print(f"      Q = {base64.b64encode(Q).decode()}")
                            d = privbuffer.read_mpint()
                            print(f"      d = {d}")
                        elif key_type == "ssh-ed25519":
                            enca = privbuffer.read_var_string()
                            kenca = privbuffer.read_var_string()
                            print("    Parameters:")
                            print(f"      Public Key = {base64.b64encode(enca).decode()}")
                            print(f"      Private Key = {base64.b64encode(kenca).decode()}")
                        elif key_type == "ssh-rsa":
                            n = privbuffer.read_mpint()
                            e = privbuffer.read_mpint()
                            d = privbuffer.read_mpint()
                            iqmp = privbuffer.read_mpint()
                            p = privbuffer.read_mpint()
                            q = privbuffer.read_mpint()
                            print("    Parameters:")
                            print(f"      n = {n}")
                            print(f"      e = {e}")
                            print(f"      d = {d}")
                            print(f"      iqmp = {iqmp}")
                            print(f"      p = {p}")
                            print(f"      q = {q}")
                        else:
                            print("    Unsupported key type! Can't continue parsing private keys.")
                            break
                        
                        comment = privbuffer.read_var_string().decode()
                        print(f"    comment: {comment}")
                    
                    padding = privbuffer.data[privbuffer.offset:]
                    i = 1
                    for p in padding:
                        if p != i:
                            print(f"  WARNING: Invalid Padding")
                            print(f"  {padding}")
                            break
                        i+=1
                    
                                    
                if keybuffer.remaining_bytes() > 0:
                    print(f"  unparsed data: {keybuffer.remaining_bytes()} bytes")
                
            except Exception as e:
                print("  WARNING: Parse Error")
                print(f"  {e}")
                        
        else:
            print(f"  Not an OpenSSH Private Key File")
                
    print()

class BinaryBuffer:
    def __init__(self, data):
        self.data = data
        self.offset = 0
    
    def read_uint32(self):
        num = self.data[self.offset] << 24
        num += self.data[self.offset+1] << 16
        num += self.data[self.offset+2] << 8
        num += self.data[self.offset+3] 
        self.offset += 4
        return num
    
    def read_fixed_string(self, length):
        string = self.data[self.offset:self.offset+length]
        self.offset += length
        return string
        
    def read_var_string(self):
        old_offset = self.offset
        try:
            length = self.read_uint32()
            string = self.read_fixed_string(length)
            return string
        except e:
            self.offset = old_offset
            raise e
            
    def read_mpint(self):
        str = self.read_var_string()
        num = 0
        for i in str:
            num <<= 8
            num += i
        return num
        
    def remaining_bytes(self):
        return len(self.data)-self.offset

def print_usage():
    print("Usage:")
    print(f"{sys.argv[0]} [keyfile]")
    print()


main()