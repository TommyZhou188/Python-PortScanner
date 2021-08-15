import socket
import tkinter as tk
import struct 
import threading

#Quick Scan function
def use_standard_ports():
    host = fs_hostname.get()
    port = list(range(1,10001))
    openPorts = threadingPortScan(host, port)
    output.insert(tk.INSERT, f"host:{host}\n")
    output.insert(tk.INSERT, f"open ports:{openPorts}\n\n")
    

#Given an IP and port scan whether the connection is successful
def tcpPortScan(host,port,openPort):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建套接字
    sock.settimeout(0.5)            # 设置延时时间
    
    try:
        sock.connect((host, port))
    except socket.error:
        pass
    else:
        openPort.append(port)   # 如果端口开放，就把端口port赋给openPort
    sock.close()                    # 关闭套接字


# Multi-threaded scanning function
def threadingPortScan(host,port,openPorts = []):
    host = fs_hostname.get()
    nloops = range(len(port))
    threads = []

    for i in nloops:
        t = threading.Thread(target=tcpPortScan, args=(host, port[i], openPorts))
        threads.append(t)
 
    for i in nloops:
        threads[i].start()
 
    for i in nloops:
        threads[i].join()
    return openPorts                       # 返回值为该域名下开放的端口列表

    
# Custom port number scanning function
def use_custom_port():
    host = ss_hostname.get()
    port1 = ss_port_number1.get()
    port2 = ss_port_number2.get()
    port = list(range(port1,port2+1))
    
    for i in port:
        try:
            scan = socket.socket()
            scan.settimeout(0.01)
            scan.connect((host, i))
        except socket.error:
            pass
        else:
            output.insert(tk.INSERT,
                      f"[Host] --> {host}\n[Port] {i} --> [OPEN]\n\n")
            output.see(tk.END)
    output.insert(tk.INSERT,"扫描结束\n\n")


# Custom IP address segment scanning function
def use_custom_port2():
    host1 = ss_hostname1.get()
    host2 = ss_hostname2.get()
    host = []
    ip1 = struct.unpack('!I', socket.inet_aton(host1))[0]
    ip2 = struct.unpack('!I', socket.inet_aton(host2))[0]
    port = list(range(1,1001))
    for ip_int in range(ip1 ,ip2 + 1):
        host.append(socket.inet_ntoa(struct.pack('!I', ip_int)))
           
    for i in port:
        for j in range(0,ip2 - ip1 + 1):
            try:
                scan = socket.socket()
                scan.settimeout(0.01)
                scan.connect((host[j], i))
            except socket.error:
                pass
            else:
                output.insert(tk.INSERT,
                      f"[Host] --> {host[j]}\n[Port] {i} --> [OPEN]\n\n")
                output.see(tk.END)
    output.insert(tk.INSERT,"扫描结束\n\n")

def do_selection():
    if rvar.get() == 0:
        output.delete('1.0', tk.END)
        fast_scan()
    elif rvar.get() == 1:
        special_scan()
    elif rvar.get() == 2:
        special_scan2()


def fast_scan():
    # Quick-Scan Gui
    fs = tk.Toplevel(None)
    fs.geometry("255x100+600+300")
    fs.resizable(width=False, height=False)
    fs.config(bg="LightGrey")

    # Output Window
    host_entry = tk.Entry(fs, textvariable=fs_hostname, width=22)
    host_entry.focus()
    host_entry.place(x=10, y=35)

    label_host_input = tk.Label(fs, text="HOST:")
    label_host_input.place(x=10, y=7)
    label_host_input.config(bg="LightGrey", font=('', 12))

    scan_btn = tk.Button(fs, text="扫描", command=fs.destroy, width=18)
    scan_btn.place(x=10, y=60)
    scan_btn.config(bg="LightGrey", font=('', 9))

    fs.wait_window()  
    use_standard_ports()


def special_scan():
    # custom Gui
    ss = tk.Toplevel(None)
    ss.geometry("620x300+600+300")
    ss.resizable(width=False, height=False)
    ss.config(bg="LightGrey")

    
    # Window button
    label_host = tk.Label(ss, text="HOST:", font=('', 12))
    label_host.place(x=5, y=5)
    label_host.config(bg="LightGrey")
    
    label_port1 = tk.Label(ss, text="PORT:", font=('', 12))
    label_port1.place(x=300, y=5)
    label_port1.config(bg="LightGrey")
    
    label_port2 = tk.Label(ss, text="PORT:", font=('', 12))
    label_port2.place(x=400, y=5)
    label_port2.config(bg="LightGrey")

    entry_host = tk.Entry(ss, textvariable=ss_hostname, width=15)
    entry_host.focus()
    entry_host.place(x=7, y=35)
    
    entry_port1 = tk.Entry(ss, textvariable=ss_port_number1, width=7)
    entry_port1.place(x=300, y=35)
    
    entry_port2 = tk.Entry(ss, textvariable=ss_port_number2, width=7)
    entry_port2.place(x=400, y=35)

    scan_btn = tk.Button(ss, text="扫描", width=22, command=ss.destroy)
    scan_btn.place(x=7, y=65)
    scan_btn.config(bg="LightGrey", font=('', 9))

    ss.wait_window()  
    use_custom_port()
    
def special_scan2():
    ss = tk.Toplevel(None)
    ss.geometry("620x300+600+300")
    ss.resizable(width=False, height=False)
    ss.config(bg="LightGrey")

    label_host = tk.Label(ss, text="HOST:", font=('', 12))
    label_host.place(x=5, y=5)
    label_host.config(bg="LightGrey")
    
    label_host = tk.Label(ss, text="HOST:", font=('', 12))
    label_host.place(x=150, y=5)
    label_host.config(bg="LightGrey")

    entry_host = tk.Entry(ss, textvariable=ss_hostname1, width=15)
    entry_host.focus()
    entry_host.place(x=7, y=35)
    
    entry_host = tk.Entry(ss, textvariable=ss_hostname2, width=15)
    entry_host.focus()
    entry_host.place(x=152, y=35)

    scan_btn = tk.Button(ss, text="扫描", width=22, command=ss.destroy)
    scan_btn.place(x=7, y=65)
    scan_btn.config(bg="LightGrey", font=('', 9))

    ss.wait_window()  
    use_custom_port2()


######################
# Window Gui #
######################

root = tk.Tk(None)
root.title("端口扫描器")
root.geometry("560x400+420+300")
root.resizable(width=False, height=False)
root.config(bg="LightGrey")

# Global variable
fs_hostname = tk.StringVar()
ss_hostname = tk.StringVar()
ss_hostname1 = tk.StringVar()
ss_hostname2 = tk.StringVar()
ss_port_number1 = tk.IntVar()
ss_port_number2 = tk.IntVar()

# Local variable
rvar = tk.IntVar()
rvar.set(0)

# Local button
fast_scan_rbtn = tk.Radiobutton(root, text="快速扫描",
                                variable=rvar, value=0)
fast_scan_rbtn.place(x=10, y=35)
fast_scan_rbtn.config(bg="LightGrey", font=('', 10))

special_scan_rbtn = tk.Radiobutton(root, text="自定义端口扫描",
                                   variable=rvar, value=1)
special_scan_rbtn.place(x=10, y=60)
special_scan_rbtn.config(bg="LightGrey", font=('', 10))

special_scan_rbtn = tk.Radiobutton(root, text="自定义地址段扫描",
                                   variable=rvar, value=2)
special_scan_rbtn.place(x=10, y=85)
special_scan_rbtn.config(bg="LightGrey", font=('', 10))

select_btn = tk.Button(root, text="选择",
                       command=do_selection, width=12)
select_btn.place(x=15, y=130)
select_btn.config(bg="LightGrey", font=('', 10))

clear_btn = tk.Button(root, text="清屏",
                      command=lambda: output.delete('1.0', tk.END))
clear_btn.place(x=15, y=175)
clear_btn.config(bg="LightGrey", font=('', 10), width=12)

exit_btn = tk.Button(root, text="退出", command=root.quit)
exit_btn.place(x=28, y=223)
exit_btn.config(bg="LightGrey", font=('', 10),  width=9)

output = tk.Text(root, width=39, height=24, state='normal')
output.place(x=140, y=15)

scan_type_label = tk.Label(root, text="选择扫描类型:")
scan_type_label.place(x=10, y=10)
scan_type_label.config(bg="LightGrey", font=('', 10))

root.mainloop()  
