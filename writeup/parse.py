import sys
lines = open(sys.argv[1]).readlines()
builder = ''
for line in lines[1:]:
    values = line.split(',')
    if 'Standard query response' in line:
        #print('command', values)
        addr = values[-1].split('AAAA')[-1].replace('"','').replace(' ','').strip()
        chunks = addr.split(':')
        real_addr=''
        for chunk in chunks:
            if chunk=='0':
                real_addr+='00'
            else:
                real_addr+=chunk

        #print('addr',real_addr)
        try:
            print('cmd',bytes.fromhex(real_addr).decode('ascii'))
        except:
            print('error', real_addr)
    else:
        name = values[-1].split('AAAA')[-1]
        labels = name.split('.')
        if labels[0].strip() == '474f415453':
            print('heartbeat')
            continue
        count = int(labels[0])
        parameter = labels[1]
        
        builder+=parameter
        if count==0:
            try:
                b= bytes.fromhex(builder)
                txt = b.decode('ascii')
                print('resp',txt)
            except:
                print('error',builder)
