;
; BIND data file for miek.nl for internal use
;
$TTL    1H
@       IN      SOA     elektron.atoom.net. miekg.atoom.net. (
                     2002120700         ; Serial
                             6H         ; Refresh
                             2H         ; Retry
                             7D         ; Expire
                             1H )       ; Negative Cache TTL

@       IN      NS      elektron.atoom.net.
@	IN	MX	10 elektron.atoom.net.
@	IN	DS	12345 3 1 123456789abcdef67890123456789abcdef67890
www	IN	DS	54321 1 1 1123456789a bcdef67890123456789abcdef6789
nl      IN      KEY 256 3 5 (
                                AQOppkQvFlPFLiWZc0NXX5/QY44jphv3vfX0dscHNmTh
                                Ntfx0TUgfBb1YQKJX6MNrzu/vvtV3xpLcCJ+tIP8ADDi
                                MaUYT5Gh6kmn22V7FgHPlCHRJ+AcudQbeYgw1KCYS9D4
                                6oEvBR8mQ4HFTEkdWg+PETATQk77P1CmmURdogcmzZqZ
                                Ier+VAs6uusIdxrmWeP8j2aYRvozdjvgzmHXSabDDxrn
                                uIbnL4r4qAoc6Q9DAybYA7Ya52gtH06dFOkaQr1dvHu1
                                iJES16H0SL/OlhsOVrZmM1RFcwDGXcnxiKZ4TdtFeXQ/
                                6VN3JegLR5t2FyKzoKYb4klpdZM8JVuVtc/n
                                ) ; key id = 61154

