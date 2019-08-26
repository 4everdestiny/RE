from pwn import *
import sys
import os

if len(sys.argv) < 2:
    debug = True
    inputf = "inputf"
    outputf = "outputf"
else:
    debug = False

if debug:
    pass
else:
    outputf = "output.file"

p = 0
code_base = 0x555555554000
def debugf(b):
    global p
    if debug:
        p = gdb.debug(args = ["./babyre",inputf,outputf],exe = "./babyre",gdbscript = "b *{b1}".format(b1 = hex(code_base + b)))

def parse_input():
    binlist = []
    for x in info:
        mask = 0x80
        temp = ord(x)
        while mask != 0:
            if temp & mask != 0:
                binlist.append(1)
            else:
                binlist.append(0)
            mask = mask >> 1
    index = 0
    res = ""
    times = 0
    window = ["\x00" for i in range(0x1000)]
    window_index = 1
    while index < len(binlist) - 0x18:
        if index % 0x10000 == 0:
            log.success("index length:" + hex(index) + "&" + hex(len(binlist)))
        #print res
        if binlist[index] == 1:
            index += 1
            temp = 0
            for i in range(8):
                temp *= 2
                temp += binlist[index]
                index += 1
            res += chr(temp)
            window[window_index & 0xfff] = chr(temp)
            window_index += 1
        else:
            tempi = ""
            for i in range(17):
                tempi += str(binlist[i + index])
            #log.info("this turn:" + tempi)
            index += 1
            temp = 0
            for i in range(12):
                temp *= 2
                temp += binlist[index]
                index += 1
            index_c = temp
            temp = 0
            for i in range(4):
                temp *= 2
                temp += binlist[index]
                index += 1
            for i in range(temp + 2):
                #print index_c,res
                window[window_index & 0xfff] = window[index_c & 0xfff]
                window_index += 1
                res += window[index_c & 0xfff]
                index_c += 1
            #add_res = res[index_c : index_c + temp + 2]
            #res += add_res
            #log.info("this turn res:" + res)
            #if "flag{" in res:
            #    print res
            #    break
    if not debug:
        with open("res","w") as f:
            f.write(res)
    #print "ouput:" + res
    #print "ignore_times:" + str(times)

context.log_level = "debug"
if debug:
    with open(inputf,"w") as f:
        #itemp = "c\x00ccceeeefffffffeeddddddfasdfacxzasdweqewqdxczxcaddsdsdsdsdsd"
        #itemp = "a" * 0x10 + "\x00" * 0x10
        itemp = "a" * 0x1000 + "b" * 0x1000
        log.success("input:" + itemp)
        f.write(itemp)
    os.system("./babyre {inputf} {outputf}".format(inputf = inputf,outputf = outputf))
with open(outputf,"r") as f:
    info = f.read()
        #print info.encode("hex")
parse_input()
print "input:" + itemp
#p.interactive()
