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

a       1800    IN A    213.154.224.37
                        1800    SIG     A 1 4 1800 20030703091602 (
                                        20030603091602 21911 secure.miek.nl.
                                        ps+sAODNYoLg5chU0TNsUivSfDVh+0/pEXDV
                                        0GOPo/7bJb0+4GNV8EUJQLluYAOcA+A5ETIt
                                        w+xiTsEIBU8u4xq7CL69slXusVweJgZu/W78
                                        7kVWgDFxQGsQ5gKMsR8OD4qFaagDYevyCLsm
                                        lNlfp4EI/Vv9EHMVq8wbbZmebHM= )
                        1800    NXT     localhost.secure.miek.nl. A SIG NXT
                        1800    SIG     NXT 1 4 1800 20030703091602 (
                                        20030603091602 21911 secure.miek.nl.
                                        YhIlzxvoQLc3rYCwHdQrHWIVE8Z4DZ0qzcmt
                                        kvqXtybgFRECO1mel2sNKPXO3srSgLaUnDKq
                                        EToM5DJi9UCqmtkTUm80EA8Wy/NsKsXAHD89
                                        5Q1RoRYmPs42s7+0w3sOi0/rMa9L6Tsiy5xN
                                        odCINY5zeBfJhfQ63tv5vH0JtsM= )

