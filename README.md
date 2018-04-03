## Service ##

- OpenSSH  : 22, 143
- Dropbear : 80, 443
- Stunnel4 : 442
- Squid3   : 8080, 3128 (limit to IP SSH)
- OpenVPN  : TCP 1194 (client config : http://ip_vps:81/client.ovpn)
- badvpn   : badvpn-udpgw port 7300
- nginx    : 81

## Script ##

- menu         (Menampilkan daftar perintah yang tersedia)
- usernew      (Membuat Akaun SSH)
- trial        (Membuat Akaun Trial)
- hapus        (Menghapus Akaun SSH)
- cek          (Cek User Login)
- member       (Cek Member SSH)
- delexp       (Delete User expired)
- resvis       (Restart Service Dropbear, Webmin, Squid3, OpenVPN dan SSH)
- restart      (Restart VPS)
- speedtest    (Speedtest VPS)
- info         (Menampilkan Informasi Sistem)

## Fitur lain ##

- DDoS Deflate
- Webmin
- Timezone : Asia/Kuala Lumpur (GMT +8)
- IPv6     : [off]

## Installation ##

Copy dan paste command di bawah dn tekan ENTER. Tunggu sampai proses siap.

`apt-get update && apt-get install ca-certificates && wget https://raw.githubusercontent.com/NerdsBay/autoscript/master/debian7.sh && chmod +x debian7.sh && ./debian7.sh`

## Website ##

- https://nerdsbay.gq/
