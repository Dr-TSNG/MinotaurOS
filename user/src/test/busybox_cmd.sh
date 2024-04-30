busybox echo "#### independent command test"
busybox ash -c exit
busybox sh -c exit
busybox basename /aaa/bbb
busybox cal
busybox clear
busybox date
busybox df
busybox dirname /aaa/bbb
busybox dmesg
busybox du
busybox expr 1 + 1
busybox false
busybox true
busybox which ls
busybox uname
busybox uptime
busybox printf "abc\n"
busybox ps
busybox pwd
busybox free
busybox hwclock
busybox kill 10
busybox ls
busybox sleep 1
busybox echo "#### file opration test"
busybox touch test.txt
busybox echo "hello world" > test.txt
busybox cat test.txt
busybox cut -c 3 test.txt
busybox od test.txt
busybox head test.txt
busybox tail test.txt
busybox hexdump -C test.txt
busybox md5sum test.txt
busybox echo "ccccccc" >> test.txt
busybox echo "bbbbbbb" >> test.txt
busybox echo "aaaaaaa" >> test.txt
busybox echo "2222222" >> test.txt
busybox echo "1111111" >> test.txt
busybox echo "bbbbbbb" >> test.txt
busybox sort test.txt | ./busybox uniq
busybox stat test.txt
busybox strings test.txt
busybox wc test.txt
busybox [ -f test.txt ]
busybox more test.txt
busybox rm test.txt
busybox mkdir test_dir
busybox mv test_dir test
busybox rmdir test
busybox grep hello busybox_cmd.txt
busybox cp busybox_cmd.txt busybox_cmd.bak
busybox rm busybox_cmd.bak
busybox find -name "busybox_cmd.txt"
