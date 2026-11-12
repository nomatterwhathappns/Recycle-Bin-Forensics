# Memahami Recycle Bin Forensics dari byte sampai laporan

Panduan ini menjelaskan Recycle Bin Forensics **1.3.0**: masalah yang diselesaikan, teknologi yang digunakan, kode yang menentukan hasil, dan cara menafsirkan temuan. Contoh path, pengguna, dan kasus di sini fiktif. Versi aplikasi `1.3.0` berbeda dari versi kontrak laporan JSON `2.0`.

## 1. Apa yang sebenarnya kita buat?

Kita membuat **parser artefak forensik dan toolkit triase offline**. Input-nya file metadata `$I` atau folder hasil akuisisi. Selain membaca metadata, tool menginventaris payload tanpa metadata, memilih temuan dengan filter, membangun timeline, dan membuat laporan HTML mandiri. Versi 1.1 menambahkan antarmuka desktop yang memakai mesin analisis sama; versi 1.2 memperluas ruang baca, detail, pengaturan teks, dan sorting tampilannya. Output-nya bisa diperiksa manusia dan diproses alat lain.

Pada Recycle Bin Windows modern, satu item dapat mempunyai dua pasangan:

```text
$IABC123.docx  -> metadata
$RABC123.docx  -> data file, jika masih ada
```

Metadata biasanya mencatat path asli, ukuran asli, dan waktu penghapusan. `$R` dapat berupa file atau folder. Nama pasangan ditentukan oleh suffix yang sama, bukan dengan membuka path asli yang tertulis di metadata.

Contoh: metadata berisi `C:\Users\Demo\Documents\catatan.txt`. Tool menampilkan teks itu sebagai temuan. Tool tidak membuka path tersebut di komputer analis. Pasangan yang dicari adalah `$R...` di folder salinan bukti yang sama.

Pemisahan ini sangat penting: **mengetahui jejak file bukan berarti kontennya berhasil dipulihkan**. `$I` bisa masih tersedia ketika `$R` sudah hilang. Sebaliknya, `$R` tanpa metadata tidak otomatis memberikan path dan waktu penghapusan.

## 2. Teknologi yang dipakai, dan alasannya

| Teknologi | Peran di proyek | Alasan penggunaannya |
| --- | --- | --- |
| Python 3.10+ | Bahasa implementasi | Mendukung byte, integer besar, CLI, dan filesystem tanpa banyak dependensi |
| `struct` | Membaca integer dari byte | Ukuran field dan endianness bisa ditulis eksplisit |
| UTF-16LE decoder | Membaca path Windows | Sesuai encoding path di format yang didukung |
| `datetime` dan aritmetika integer | Menafsirkan FILETIME | Timestamp UTC bisa dihitung tanpa pembulatan float |
| `zoneinfo` | Tampilan zona waktu opsional | Menggunakan basis data IANA, bukan menebak offset komputer |
| `hashlib` / SHA-256 | Sidik jari byte metadata dan payload opsional | Memudahkan perbandingan byte yang dibaca |
| `pathlib`, `os`, dan pemeriksaan metadata file | Pemindaian artefak | Memisahkan path bukti lokal dari teks path Windows di dalam artefak |
| `argparse` | Antarmuka terminal | Parsing argumen, bantuan penggunaan, dan error pemakaian |
| `json` dan `csv` | Ekspor laporan | Mudah dipakai otomatisasi, spreadsheet, dan alat analisis lain |
| `html` dan JavaScript lokal | Laporan HTML offline | Menampilkan inventaris dan timeline tanpa server; data bukti di-escape sebelum ditampilkan |
| `tkinter` / `ttk` | Antarmuka desktop lokal | Dialog file, tabel, detail, dan kontrol tanpa server web |
| `threading`, queue, dan `contextvars` | Pekerjaan latar, progress, pembatalan | Memisahkan pekerjaan scan dari event loop GUI dan menjaga kontrol tiap run terisolasi |
| PyInstaller | Paket Windows portable | Membundel Python, Tcl/Tk, dan data zona waktu menjadi folder aplikasi yang dapat dijalankan |
| `pytest` | Pengujian | Memastikan byte yang diketahui menghasilkan nilai atau error yang diharapkan |
| Ruff | Pemeriksaan dan format kode | Menemukan kesalahan umum dan menjaga konsistensi |
| Setuptools / `pyproject.toml` | Packaging | Membuat paket yang dapat dipasang dan command `rbf` |
| GitHub Actions | CI | Menjalankan pemeriksaan otomatis ketika kode berubah |

Operasi UTC tidak membutuhkan dependensi runtime dari pihak ketiga. `tzdata` hanya diperlukan jika sistem tidak menyediakan basis data zona waktu yang dibutuhkan. Ini sering relevan pada Windows.

Tidak ada server, database, layanan cloud, atau upload bukti pada alur analisis tool ini. GitHub digunakan untuk menyimpan dan mengembangkan source code.

## 3. Alur satu perintah

```sh
rbf scan work/demo --recursive --format json --output work/report.json
```

Alurnya:

```text
argumen pengguna
      |
      v
validasi input dan tujuan laporan
      |
      v
temukan kandidat $I dan $R secara deterministik
      |
      v
baca byte + hitung SHA-256 metadata
      |
      v
parse header, panjang, path, dan FILETIME
      |
      v
periksa pasangan $R + hash jika diminta dan aman
      |
      v
kumpulkan hasil, warning, error, dan konteks pemindaian
      |
      v
pilih view dengan filter tanpa menghapus inventaris penuh
      |
      v
bangun timeline dari timestamp penghapusan yang valid
      |
      v
render table / JSON / CSV / HTML + exit code
```

Modul-modul utama memisahkan tanggung jawab:

- [`parser.py`](../src/rbinforensics/parser.py): mengubah `bytes` menjadi nilai metadata; tidak mengakses filesystem.
- [`scanner.py`](../src/rbinforensics/scanner.py): menemukan dan membaca artefak, menghitung hash, serta memeriksa payload.
- [`analysis.py`](../src/rbinforensics/analysis.py): memilih record dengan filter dan membangun timeline dari nilai metadata.
- [`reports.py`](../src/rbinforensics/reports.py): menyajikan hasil tanpa mengubah cara byte ditafsirkan.
- [`html_report.py`](../src/rbinforensics/html_report.py): merender view HTML offline dengan perlindungan teks bukti.
- [`cli.py`](../src/rbinforensics/cli.py): memvalidasi argumen dan menghubungkan komponen menjadi command.
- [`gui.py`](../src/rbinforensics/gui.py): membangun jendela desktop dan mengubah event worker menjadi tampilan.
- [`desktop.py`](../src/rbinforensics/desktop.py): mengelola state, thread, hasil lengkap, view, serta pekerjaan ekspor tanpa mengakses widget.
- [`scan_control.py`](../src/rbinforensics/scan_control.py): sinyal pembatalan dan notifikasi progress untuk satu run.
- [`output.py`](../src/rbinforensics/output.py): satu implementasi penulisan laporan yang dipakai CLI dan desktop.

Pemisahan ini memungkinkan kita menguji parser dengan satu buffer byte, tanpa membutuhkan Windows atau file bukti asli. Pemeriksaan filesystem bisa diuji terpisah lewat direktori sementara.

## 4. Kode penting pertama: membaca header dengan benar

Di `parse_metadata`, inti pembacaan header adalah:

```python
version, size, ticks = struct.unpack_from("<QQQ", data, 0)
```

Makna setiap bagiannya:

- `<` memilih little-endian. Byte paling rendah berada di alamat paling awal.
- `Q` membaca unsigned integer 64-bit, yaitu 8 byte.
- `QQQ` membaca tiga nilai berurutan: versi, ukuran asli, dan FILETIME.
- `0` adalah posisi awal pembacaan di dalam buffer.

Sebelum baris ini dijalankan, panjang data diperiksa. Header membutuhkan minimal 24 byte. Kalau hanya ada 10 byte, tool harus melaporkan `truncated_header`, bukan mencoba menebak sisanya.

Misalnya angka `1` dalam field 8 byte little-endian ditulis:

```text
01 00 00 00 00 00 00 00
```

Memilih endianness atau ukuran integer yang salah dapat menghasilkan angka yang terlihat valid tetapi sepenuhnya salah. Itulah alasan layout binary ditulis eksplisit dan diuji.

Nilai versi tidak diterjemahkan langsung menjadi “Windows 10” atau “Windows 11”. Yang pasti kita ketahui dari field ini adalah versi format artefaknya.

## 5. Mengapa ada dua cara membaca path?

Format versi 1 mempunyai field path tetap sepanjang **520 byte**, yaitu 260 code unit UTF-16. Total ukuran normalnya 24 + 520 = **544 byte**.

Format versi 2 mempunyai field panjang path empat byte di offset 24. Path dimulai di offset 28. Parser membaca panjangnya dengan:

```python
(units,) = struct.unpack_from("<I", data, V2_LENGTH_OFFSET)
expected = V2_PATH_OFFSET + units * 2
```

Di format string ini, `I` berarti unsigned integer 32-bit, bukan awalan nama file `$I`.

Kenapa dikali dua? Karena panjang dinyatakan dalam code unit UTF-16 dan satu code unit berukuran dua byte. Nilai tersebut memasukkan NUL penutup.

Parser memeriksa bahwa:

1. Field panjang tersedia.
2. Nilainya berada dalam batas yang didukung, `1..32768` code unit.
3. Seluruh byte path yang dideklarasikan benar-benar tersedia.

Jika file mengaku punya path sepanjang 100 code unit tetapi hanya menyediakan 20 byte, hasilnya `truncated_path`. Tool tidak memotong dan menyajikan path parsial seolah lengkap.

Batas panjang juga melindungi parser dari nilai yang tidak masuk akal. Angka di dalam bukti tetap diperlakukan sebagai input yang perlu divalidasi.

## 6. UTF-16: kenapa `len(path)` bisa salah?

Python menghitung karakter Unicode, sementara format ini menghitung code unit UTF-16. Banyak karakter umum menggunakan satu code unit. Karakter seperti `📄` membutuhkan dua code unit melalui surrogate pair.

Karena itu, saat membuat contoh versi 2 kita menggunakan:

```python
encoded_path = original_path.encode("utf-16-le") + b"\x00\x00"
units = len(encoded_path) // 2
```

Menggunakan `len(original_path) + 1` akan salah untuk beberapa karakter Unicode. Contoh generator menyertakan emoji agar kasus ini terlihat dan bisa diuji.

Untuk membaca kembali path, parser memakai decoding ketat:

```python
path = field.decode("utf-16-le", errors="strict")
```

Jika ada surrogate yang tidak mempunyai pasangan valid, parser mengeluarkan `invalid_utf16`. Menggunakan mode `replace` akan menyisipkan karakter pengganti `�`, sehingga path yang ditampilkan tidak lagi sama dengan representasi byte aslinya.

### Mengapa pencarian terminator harus per dua byte?

Huruf ASCII dalam UTF-16LE memiliki byte nol di setiap byte kedua. Mencari sembarang `b"\x00\x00"` dapat menemukan dua nol yang tumpang tindih dengan batas antar-code-unit.

Parser versi 1 memeriksa posisi `0, 2, 4, ...`:

```python
field[i : i + 2] == b"\0\0"
```

NUL pertama mengakhiri path versi 1. Sisa field tetap dianggap padding, dan padding yang berisi byte bukan nol menghasilkan warning. Versi 2 menggunakan panjang yang dideklarasikan; NUL di tengah teks ditandai agar tidak disembunyikan sebagai path biasa.

## 7. Kode penting FILETIME: mempertahankan 100 nanodetik

FILETIME adalah hitungan interval **100 ns sejak 1 Januari 1601 UTC**. Satu detik mengandung 10.000.000 tick.

Inti konversinya:

```python
seconds, fraction = divmod(ticks, 10_000_000)
value = FILETIME_EPOCH + timedelta(seconds=seconds)
```

`divmod` memberikan hasil bagi dan sisa sekaligus. `seconds` dipakai untuk menghitung tanggal dan jam, sedangkan `fraction` diformat menjadi tujuh digit:

```text
2026-01-15T03:04:05.1234567Z
```

Digit `7` paling akhir tidak boleh hilang. Python `datetime` sendiri hanya menyimpan presisi mikrodetik, yaitu enam digit pecahan. Dengan menghitung detik bulat dan memformat sisa integer secara terpisah, parser mempertahankan seluruh presisi nilai asal.

Kenapa tidak langsung memakai float? Karena float tidak dapat mewakili semua integer besar dengan tepat. Pembagian float atau konversi timestamp yang ceroboh dapat membulatkan tick.

Nilai mentah tetap disertakan agar konsumen bisa memeriksa konversinya. Jika timestamp nol atau di luar rentang tanggal yang bisa direpresentasikan, tool memberikan nilai waktu yang tidak tersedia beserta warning. Mengganti nilai anomali dengan waktu sekarang akan menciptakan temuan palsu.

Zona waktu tampilan tidak mengubah tick atau UTC asal. Contohnya, waktu `03:04:05Z` yang sama tampil `10:04:05+07:00` dalam `Asia/Jakarta`. Jangan membandingkan dua laporan hanya dari jamnya tanpa melihat timezone.

## 8. Error berbeda dengan warning

`ParseError` membawa kode yang dapat digunakan program lain:

```python
raise ParseError("truncated_path", "...")
```

Contoh error struktural:

- Header tidak lengkap.
- Format versi tidak didukung.
- Panjang path tidak valid.
- Byte path kurang dari deklarasinya.
- UTF-16LE tidak valid.

Parser tidak mengembalikan objek metadata normal untuk kasus tersebut. Scanner menangkap kegagalan per file sehingga artefak lain tetap dapat diproses.

Warning menunjukkan nilai berhasil dibaca tetapi ada sesuatu yang perlu diperiksa. Contohnya `trailing_data`, `missing_path_terminator`, `nonzero_path_padding`, `embedded_nul_in_path`, atau waktu penghapusan nol. Warning tidak membuktikan pemalsuan; bisa berasal dari data tidak lazim, kerusakan, atau asumsi format yang perlu diperiksa.

`Metadata` menggunakan dataclass yang dibekukan:

```python
@dataclass(frozen=True)
class Metadata: ...
```

Ini membantu mencegah komponen berikutnya mengubah nilai hasil parsing tanpa sengaja. Presentasi lokal, CSV, atau JSON sebaiknya menyajikan hasil itu, bukan mengeditnya.

## 9. Scanner: hubungan kode dengan perlakuan bukti

Parser tidak tahu dari mana data datang. Scanner bertugas membuat hubungan antara byte, lokasi artefak, dan hasilnya tetap jelas.

Hal-hal yang perlu dibaca saat mempelajari `scanner.py`:

1. **Penemuan kandidat.** Mode direktori mencari nama metadata `$I`; mode recursive menelusuri folder turunannya. Urutan yang deterministik memudahkan perbandingan dua run.
2. **Pemeriksaan link dan jenis file.** Link bukan file biasa yang aman dibuka tanpa pemeriksaan. Tool menghindari mengikuti symlink bukti dan tidak memperlakukan folder sebagai byte stream.
3. **Pembacaan dan hash metadata.** SHA-256 harus dihitung dari byte yang benar-benar dibaca dan ditafsirkan, bukan dari hasil decode atau JSON-nya.
4. **Parsing per kandidat.** Satu exception dari satu file harus menjadi hasil error file itu, bukan menghilangkan temuan yang lain.
5. **Korelasi payload.** Ubah awalan nama `$I` menjadi `$R` dengan suffix yang sama di folder akuisisi. Jangan gunakan `original_path` untuk mencari konten di komputer pemeriksa.
6. **Hash payload opsional.** `--hash-payload` menambah pekerjaan membaca konten file reguler. Tanpa flag ini, jangan berasumsi hash payload sudah diverifikasi.

Folder payload bisa diidentifikasi keberadaannya, tetapi tool tidak menghasilkan hash isi folder secara rekursif. Merancang hash sebuah folder membutuhkan definisi tambahan: urutan item, nama, tipe, isi, link, dan penanganan file yang tidak terbaca. Karena belum didefinisikan di sini, tool tidak menyamarkan keberadaan folder sebagai hash konten yang lengkap.

Pencocokan nama mengabaikan perbedaan huruf besar/kecil ASCII dan menambahkan warning jika ejaannya tidak persis sama. Tool tidak memakai Unicode `casefold()` untuk korelasi karena, misalnya, `ß` bisa berubah menjadi `ss` dan memasangkan dua item berbeda pada salinan filesystem. Jika ada lebih dari satu pasangan yang cocok, hasilnya ambigu dan tool tidak memilih salah satunya secara diam-diam.

Perlindungan tool bukan pengganti media read-only. Filesystem yang berubah saat dipindai dapat membuat hasil tidak konsisten. Membaca file juga dapat mengubah access time pada mount yang writable.

Kode `_open_regular` melakukan beberapa pemeriksaan penting:

```python
before = path.lstat()
descriptor = os.open(path, flags)
opened = os.fstat(stream.fileno())
```

`lstat()` memeriksa objek path tanpa mengikuti link terakhir. Setelah file dibuka, `fstat()` memeriksa objek yang benar-benar dibuka. Scanner membandingkan identitas perangkat/inode, ukuran, dan mtime antara path dan file handle. Perbandingan sebelum/sesudah melalui API yang sama juga mencakup ctime: `lstat` dibandingkan dengan `lstat`, serta `fstat` dengan `fstat`. Pada platform yang mendukungnya, flag `O_NOFOLLOW` ikut menolak link terakhir dan `O_NONBLOCK` mencegah pergantian menjadi FIFO membuat proses menunggu tanpa batas.

Ada penyesuaian khusus Windows di `_cross_api_identity`. Saat pengujian Windows dengan Python 3.13, `lstat()` dan `fstat()` bisa melaporkan ctime yang berbeda beberapa milidetik untuk file yang tidak berubah. Karena itu, hanya perbandingan **lintas kedua API pada Windows** yang mengecualikan ctime; pemeriksaan perangkat/inode, ukuran, dan mtime tetap berlaku. Pemeriksaan ctime sebelum/sesudah melalui API yang sama tetap dipertahankan. Ini menyangkut timestamp metadata filesystem yang dikembalikan `os.stat`, bukan field waktu penghapusan di dalam byte `$I`. Konversi deletion FILETIME tetap menggunakan nilai mentah dan mempertahankan tujuh digit pecahan detik. Lihat juga [dokumentasi atribut `os.stat_result`](https://docs.python.org/3/library/os.html#os.stat_result) untuk perbedaan semantik dan ketersediaan timestamp antarplatform.

Pemeriksaan symlink juga berlaku pada komponen induk dan Windows reparse point. Ini bisa menolak path yang tampak biasa tetapi melewati redirect. Gunakan path langsung menuju working copy. Pemeriksaan tersebut mengurangi risiko salah baca atau pembacaan yang berubah; filesystem yang dimutasi secara bersamaan tetap bukan sumber bukti yang baik.

Pembacaan metadata dibatasi 128 KiB per file. File yang melebihi batas menghasilkan error tanpa SHA-256 metadata karena byte lengkapnya tidak dibaca. File yang berhasil dibaca tetapi gagal parsing tetap mempunyai hash sumber.

## 10. SHA-256: apa yang dijamin dan apa yang belum?

Secara konsep, hashing streaming melakukan:

```python
digest = hashlib.sha256()
# Baca blok, lalu digest.update(block) untuk setiap blok.
fingerprint = digest.hexdigest()
```

Streaming mencegah file payload besar harus dimuat seluruhnya ke RAM. Hash metadata diberikan terpisah dari hash konten `$R` karena keduanya adalah objek yang berbeda.

Jika dua salinan menghasilkan SHA-256 yang sama, itu memberikan dasar kuat bahwa byte yang di-hash sama. Hash tidak menjelaskan:

- Siapa yang membuat atau menghapus file.
- Apakah metadata sudah dimanipulasi sebelum pengambilan.
- Apakah koleksi seluruh artefak lengkap.
- Bagaimana bukti berpindah tangan.
- Apakah jam sumber benar.

Itulah alasan acquisition notes dan chain of custody tetap harus dikelola di luar tool.

## 11. Reports dan CLI: mengapa ekspor juga menentukan keandalan?

Laporan sebaiknya menyimpan konteks run, pilihan yang dipakai, sumber metadata, hasil parsing, pemeriksaan payload, serta error. Angka ringkasan membantu melihat kelengkapan pemrosesan, tetapi rincian setiap file tetap perlu diperiksa.

JSON adalah pilihan utama untuk integrasi program karena strukturnya eksplisit dan teks path dapat dipertahankan. CSV berguna untuk filter dan pengurutan di spreadsheet. Nilai yang berawalan karakter formula harus diperlakukan hati-hati saat membuka CSV; representasi tampilan yang dilindungi mungkin berbeda dari teks bukti persisnya. Gunakan JSON dan byte asal untuk pemeriksaan teks yang presisi.

Beberapa konsumen JSON mempunyai keterbatasan integer besar. JavaScript `Number`, misalnya, tidak mewakili semua integer 64-bit dengan tepat. Periksa representasi field FILETIME di laporan dan gunakan pembacaan lossless untuk nilai besar; jangan membulatkan raw tick saat memindahkannya ke sistem lain.

Laporan terminal tidak cocok menjadi kontrak parser program. Path dapat mengandung karakter kontrol atau karakter Unicode, dan tabel bisa berubah demi keterbacaan. Gunakan format terstruktur untuk otomatisasi.

Di `reports.py`, `safe_text` mengubah karakter kontrol menjadi teks escape sebelum dicetak ke terminal. Ini mencegah teks bukti seperti escape sequence diperlakukan sebagai instruksi terminal. `_csv_text` menambah perlindungan pada teks yang, setelah whitespace awal, dimulai dengan `=`, `+`, `-`, atau `@`. Mengapit cell CSV dengan tanda kutip saja belum mencegah spreadsheet menafsirkan formula.

JSON menggunakan encoding escape yang dapat dibaca kembali sebagai teks asal, berbeda dari representasi terminal/CSV yang dilindungi. Detail field dan status ada di [REPORT_SCHEMA.md](REPORT_SCHEMA.md).

Tujuan `--output` harus berada di luar pohon input bukti. Untuk input satu file, direktori induk file itu dianggap sebagai direktori bukti sehingga output juga harus berada di luarnya. Direktori tujuan laporan harus sudah ada.

Kode CLI membuka output dengan mode `x`, bukan `w`:

```python
with output.open("x", encoding="utf-8", newline="") as stream:
    stream.write(text)
```

Mode exclusive creation ini menolak file yang sudah ada. Sebelum menulis, tujuan divalidasi ulang; setelah menulis buffer di-flush dan descriptor di-sync. Jika proses penulisan gagal, CLI berusaha menghapus file laporannya yang belum lengkap. Ini membantu mencegah laporan bercampur dengan bukti atau menghancurkan hasil run sebelumnya. Tetap simpan laporan dan bukti dengan prosedur kasus yang benar.

Gunakan `--output` saat menyimpan hasil. Jika lo memakai `>` di shell, shell dapat membuka dan mengosongkan file tujuan sebelum program ini jalan. Perlindungan destination pada CLI tidak berlaku untuk path redirection yang tidak diketahuinya.

File payload di-hash secara streaming, tetapi seluruh record dan hasil render laporan dikumpulkan di memori. Untuk kasus sangat besar, bagi input menjadi scope yang terdokumentasi, misalnya per volume atau SID, dan simpan laporan terpisah.

Exit code memberi sinyal cepat:

- `0`: selesai tanpa error; warning masih perlu ditinjau.
- `1`: ada error pada record/discovery atau item dilewati; baca rincian sebelum menyimpulkan.
- `2`: pemakaian/konfigurasi salah, kegagalan input/output tingkat run, atau tidak ada kandidat artefak dalam scope.
- `130`: operator menginterupsi proses; pemindaian belum lengkap.

Exit `0` tidak berarti semua file yang pernah dihapus berhasil ditemukan. Tool hanya memproses apa yang ada dalam scope input dan format yang didukung.

## 12. Kapan dan oleh siapa tool ini berguna?

### Responder insiden di organisasi

Seorang analis SOC/DFIR menerima hasil akuisisi laptop yang dicurigai dipakai saat insiden. Ia mencari artefak penghapusan executable, script, atau arsip pada rentang waktu tertentu. Tool membantu menyusun daftar path dan timestamp untuk dicocokkan dengan log, `$MFT`, `$UsnJrnl`, atau artefak lain.

Temuan ini menjadi petunjuk triase. Metadata Recycle Bin sendirian tidak membuktikan bahwa suatu file adalah malware atau siapa yang menjalankannya. Penghapusan permanen bisa melewati Recycle Bin.

### Pemeriksa forensik atau investigator internal

Dalam pemeriksaan yang berwenang, nama dokumen tertentu bisa menjadi kata kunci awal. Metadata dapat membantu menjawab apakah path tertentu tercatat di artefak yang tersedia dan kapan penghapusannya direkam.

Isi dokumen tetap perlu divalidasi dari konten atau sumber lain. Folder SID juga bukan bukti tunggal identitas pelaku. Pemalsuan artefak, ketidakakuratan jam, dan kelengkapan akuisisi perlu dipertimbangkan.

### Tim dukungan dan recovery triage

Tim IT mempunyai salinan direktori Recycle Bin pengguna. Tool bisa membantu memetakan nama `$R` yang tidak jelas ke path asli dan memisahkan pasangan yang masih tersedia dari yang hilang.

Tool tidak melakukan restore. Pemulihan sebaiknya dilakukan ke lokasi baru dengan prosedur terpisah, lalu integritas dan keterbacaan konten diperiksa.

### Pengembang tool dan peserta pelatihan

Pengembang dapat menggunakannya untuk belajar format binary, pengujian kerusakan data, ketelitian timestamp, desain CLI, dan pelaporan. Untuk menguji dukungan Windows secara independen, buat file dengan nama/ukuran yang diketahui pada mesin uji, hapus secara terkontrol, akuisisi artefaknya, dan bandingkan dengan ground truth.

Contoh sintetis di repository tidak cukup untuk mengklaim seluruh variasi Windows sudah teruji. Ini batas validasi yang harus dicatat saat proyek dipresentasikan sebagai portfolio atau diadopsi tim.

## 13. Cara mempelajarinya langsung

Mulai dari data fiktif:

```sh
python examples/generate_demo.py work/belajar
rbf scan work/belajar --recursive --hash-payload --format json --output work/belajar.json
```

Lalu lakukan urutan belajar ini:

1. Buka generator. Bandingkan `struct.pack` dengan `struct.unpack_from` di parser.
2. Bandingkan path emoji dengan panjang byte hasil encoding. Hitung jumlah code unit-nya.
3. Baca test parser. Lihat bagaimana byte header, path terpotong, dan waktu batas dibentuk tanpa memanggil parser untuk membuat expected value.
4. Periksa JSON hasil scan. Cari pasangan payload yang ada dan yang sengaja tidak dibuat.
5. Jalankan generator ke direktori baru dengan `--include-broken`, lalu amati bahwa record valid tetap muncul meski exit code menjadi `1`.
6. Jalankan pengujian dan telusuri alasan setiap assertion. Jangan hanya melihat jumlah test yang lulus.

```sh
python -m pytest
python -m ruff check .
```

Jika ingin mengubah fitur, mulai dari kontraknya: byte atau keadaan input seperti apa, hasil yang diharapkan apa, dan batas yang perlu dijelaskan apa. Untuk tool forensik, error yang terlihat jelas sering lebih berguna daripada hasil tebakan yang terlihat meyakinkan.

## 14. Hal yang harus bisa lo jelaskan saat mempresentasikan proyek

- Kenapa `$I` berbeda dari `$R` dan kenapa tool ini bukan pemulih disk.
- Kenapa header dibaca dengan `<QQQ` dan apa arti offset masing-masing.
- Kenapa panjang path UTF-16 berbeda dari jumlah karakter Python.
- Kenapa FILETIME dihitung dengan integer dan disimpan bersama nilai mentahnya.
- Kenapa error file tunggal tidak menghentikan semua hasil dan warning tidak disembunyikan.
- Kenapa nama pasangan di folder bukti lebih tepat daripada membuka path asli.
- Kenapa SHA-256 membantu perbandingan byte tetapi tidak menggantikan chain of custody.
- Pengujian apa yang sudah ada dan validasi Windows independen apa yang masih diperlukan.

Pemahaman itu membuat proyek bisa dinilai dari ketelitian rekayasa dan keterbukaan batasnya, sekaligus memberi dasar untuk pengembangan berikutnya.

## 15. Inventaris lengkap: payload tanpa metadata tetap merupakan temuan

Di versi 1.0, pemindaian direktori tidak hanya dimulai dari `$I`. Scanner juga melihat `$R` yang tidak mempunyai pasangan nama metadata pada direktori yang sama. Record-nya bertipe `orphan_payload`.

Contoh:

```text
$IABC.txt + $RABC.txt  -> metadata dengan pasangan payload
$IDEF.pdf             -> metadata, payload hilang
$RGHI.bin             -> orphan payload, metadata tidak ditemukan
```

Kasus ketiga belum memberi informasi path asli atau waktu penghapusan. Nama `$RGHI.bin` adalah nama akuisisi yang diamati. Tool mempertahankan `metadata = null` dan menjelaskan keadaannya lewat issue, bukan mengisi field dengan dugaan.

Pembedaan lain yang penting: `$I` rusak masih mempunyai keberadaan sebagai counterpart. Jadi `$R` tidak boleh dilabeli orphan hanya karena parser gagal membaca `$I` tersebut. Kehilangan metadata dan kegagalan decode adalah dua keadaan berbeda.

Scanner juga tidak menelusuri isi direktori `$R` saat recursive. Sebuah folder yang dibuang dapat berisi file apa pun, termasuk nama yang kebetulan dimulai `$I`. Menganggapnya sebagai metadata Recycle Bin akan menghasilkan temuan palsu. Container bernama `$Recycle.Bin` sendiri dikecualikan dari kandidat payload.

## 16. Filter: membatasi tampilan sambil mempertahankan audit

Fungsi di `analysis.py` memisahkan dua hal: **apa yang ditemukan** dan **apa yang sedang ingin dilihat analis**.

JSON menyimpan `records` lengkap dan `summary` untuk seluruh run. `selection.record_indexes` adalah daftar posisi record yang masuk view. CSV, terminal, dan HTML memakai view tersebut. JSON masih memungkinkan orang memeriksa record yang tidak terpilih dan alasan masalah scan.

Contoh perintah:

```sh
rbf scan work/belajar --recursive --extension .pdf --extension .docx --query laporan \
  --min-size 1024 --deleted-after 2026-01-01 --format html --output work/laporan.html
```

Artinya: ekstensi PDF **atau** DOCX, lalu harus memenuhi query, ukuran, dan waktu yang diminta. Kategori filter berbeda bergabung dengan AND; ekstensi berulang menjadi alternatif dalam satu kategori.

Pencarian memakai substring literal, bukan regex. Ini membuat arti query mudah dipahami dan menghindari pola regex mahal pada koleksi besar. Filter waktu dan ukuran asli membutuhkan metadata. Payload orphan tidak mendadak memperoleh timestamp hanya supaya bisa lolos filter.

Record error, skipped, dan masalah discovery tetap ditampilkan untuk diperiksa. `selection.matched` menghitung jumlah record yang ditampilkan termasuk diagnosis wajib ini, bukan hanya temuan sukses yang cocok filter. Filter juga tidak mengubah exit code scan yang gagal menjadi sukses. Kalau filter tidak cocok dengan file rusak, keberadaan file rusak itu tetap penting untuk menilai kelengkapan analisis.

### Batas tanggal dan presisi

`--deleted-after` dan `--deleted-before` bersifat inklusif. Tanggal `2026-01-31` berarti **awal hari itu pada UTC**, bukan otomatis seluruh hari. Untuk batas akhir satu hari, tulis eksplisit:

```text
2026-01-31T23:59:59.9999999Z
```

Datetime harus membawa `Z` atau offset. `--timezone Asia/Jakarta` hanya mengubah kolom tampilan, bukan makna batas UTC/date yang dimasukkan.

GUI memberi kemudahan tambahan: tanggal **Sampai** tanpa jam diubah menjadi akhir hari UTC (`23:59:59.9999999Z`). Kalender dan label menyebut UTC. Nilai yang sudah diperluas itu dikirim sebagai batas eksplisit ke engine yang sama dan disimpan dalam selection. Jadi UI tidak perlu mengubah aturan parser/filter CLI atau kehilangan presisi; ia menerjemahkan pilihan hari pengguna menjadi parameter yang jelas.

Filter menghitung batas dengan integer tick FILETIME. Dua record yang terpisah 100 ns harus tetap bisa dibedakan. Mengubahnya dulu ke float atau membuang digit pecahan ketujuh bisa memasukkan atau mengeluarkan record yang salah tepat pada batas.

## 17. Timeline: urutan waktu yang dapat dijelaskan

`build_timeline()` mengambil record terpilih yang mempunyai metadata dan deletion time valid. Urutan utamanya adalah `deletion_filetime` mentah. Path sumber menjadi pemecah urutan ketika tick sama sehingga hasil deterministik.

Setiap event membawa path sumber dan path asli, ukuran, SID context, timestamp mentah/UTC/tampilan, serta status payload. Agregat harian dihitung pada tanggal UTC; pengelompokan SID dan ekstensi berasal dari event yang sama.

Karena record diagnosis wajib dipertahankan, metadata valid dengan error saat hashing payload bisa tetap menjadi event walaupun tidak cocok dengan query lain. Jadi timeline merangkum view yang ditampilkan, termasuk diagnosis tersebut. Periksa status record saat menafsirkan hasil filter.

Record tanpa waktu tidak dipaksakan menjadi event. Jumlahnya dicatat sebagai `undated_records`. Timestamp filesystem payload tidak digunakan untuk mengisi kekosongan deletion time karena maknanya berbeda.

Contoh penerapan: analis mencari penghapusan arsip pada rentang insiden, lalu melihat beberapa arsip tercatat dalam menit yang berdekatan. Timeline membantu memusatkan pemeriksaan. Untuk menyimpulkan apa yang terjadi, ia tetap perlu membandingkan jam sumber, log, jurnal filesystem, dan konteks akuisisi. Banyak event pada hari yang sama belum membuktikan siapa yang menghapusnya atau niatnya.

## 18. HTML offline: data bukti harus tetap menjadi teks

`html_report.py` menghasilkan satu dokumen yang bisa dibuka lokal. Style dan script ikut disimpan di dokumen. Tidak ada CDN atau server yang harus dihubungi untuk melihat laporan.

Teks bukti dapat berisi `<script>`, tanda kutip, karakter kontrol, atau nama yang terlihat seperti alamat. Memasukkannya mentah ke HTML dapat mengubah temuan menjadi markup atau script. Renderer harus meng-escape setiap nilai yang berasal dari record, label kasus, filter, atau path sebelum menaruhnya di HTML/atribut.

Kontrol browser menyeleksi dan mengurutkan baris yang sudah dirender. Ia tidak membaca ulang media bukti atau memperbaiki error parsing. Ringkasan penuh dan selection dari CLI tetap harus dibedakan dari pencarian sementara di browser.

Raw FILETIME dan ukuran uint64 juga perlu perhatian saat sorting di JavaScript. Nilai itu dapat melebihi presisi `Number`; perbandingan harus memakai representasi integer yang aman seperti `BigInt` atau pembandingan string desimal yang benar. Path bukti tidak dijadikan tautan yang membuka file asli secara otomatis.

Content Security Policy menambah pembatasan eksekusi dan akses jaringan. Perlindungan ini melengkapi escaping; ia tidak menggantikan kewajiban merender input sebagai data.

## 19. Apa arti validasi Windows yang lebih luas?

Unit test sintetis mengecek byte dan keadaan yang kita tentukan. Uji penghapusan terkontrol pada Windows asli mengecek pertanyaan lain: apakah artefak yang benar-benar dibuat Windows cocok dengan path, ukuran, hash, dan rentang waktu yang dicatat sebelum penghapusan?

Langkah lengkap dan batasnya ada di [VALIDATION_WINDOWS.md](VALIDATION_WINDOWS.md). Tes live harus membuat file disposable miliknya sendiri, mengaktifkan operasi recycle secara sengaja, menemukan pasangan yang dihasilkan, dan tidak menyentuh artefak pengguna lain. Ia tidak boleh mengosongkan seluruh Recycle Bin untuk membuat test mudah.

Satu runner Windows yang lolos hanya membuktikan skenario itu pada build dan konfigurasi tersebut. Corpus independen dari lingkungan yang akan dianalisis tetap diperlukan. Nomor versi aplikasi tidak mengubah tingkat pembuktian artefak atau menandakan sertifikasi forensik.

## 20. Desktop: memudahkan alur tanpa membuat parser kedua

GUI adalah lapisan untuk memilih sumber, menjalankan analisis, melihat hasil, dan mengekspor. Ia tetap memakai `scan()`, `apply_filters()`, `build_timeline()`, serta renderer yang sama dengan CLI. Kalau GUI mempunyai parser sendiri, perbaikan pada satu antarmuka bisa tidak masuk ke antarmuka lain dan menghasilkan interpretasi berbeda.

Alur desktop:

```text
pilihan pengguna di Tk
        |
        v
DesktopSession.start_scan()
        |
        v
worker thread -> scan() -> parser/analysis yang sama
        |
        v
queue: progress / complete / cancelled / error
        |
        v
event loop Tk membaca queue dan memperbarui widget
```

Tk mempunyai event loop: input keyboard, klik, repaint, dan callback harus tetap mendapat giliran. Membaca beberapa gigabyte payload langsung di callback tombol akan membuat jendela terlihat macet. `DesktopSession.start_scan()` membuat thread pekerja lalu segera mengembalikan kontrol. Filter dan ekspor yang besar juga dapat dikerjakan di worker.

Worker tidak memperbarui widget Tk langsung. Ia mengirim pesan melalui `SimpleQueue`. Thread GUI mengambil pesan tersebut dan mengubah label, progress, tabel, atau tombol. Pola ini memisahkan keselamatan threading dari tampilan dan membuat controller bisa diuji tanpa membuka jendela.

GUI menampilkan maksimal 200 baris per halaman agar memasukkan puluhan ribu widget tidak memblokir event loop. Batas ini hanya pada tabel. `report` lengkap, filter, timeline, dan ekspor tetap memproses inventaris sesuai scope yang dipilih. Tab review memakai seluruh record bermasalah, sedangkan tab inventaris dan timeline memakai selection.

## 21. State mencegah hasil lama dianggap sebagai scan baru

`DesktopSession` menyimpan `state`, `report`, dan `view`. `report` adalah baseline lengkap dari scan yang selesai; `view` adalah hasil seleksi dari baseline tersebut. Filter baru diterapkan ke `report`, bukan ke view sebelumnya, sehingga menekan Reset tidak kehilangan record yang sebelumnya dikeluarkan.

State penting mencakup `idle`, `scanning`, `complete`, `cancelled`, `error`, `filtering`, dan `exporting`. Memulai scan baru mengosongkan hasil lama. Pekerjaan lain ditolak selama state sedang sibuk, dan ekspor membutuhkan state `complete` serta report/view yang tersedia.

Ini melindungi dari alur yang menyesatkan: pengguna menyelesaikan kasus A, memulai kasus B lalu membatalkannya, kemudian menekan ekspor dan tanpa sadar mendapatkan hasil A. Di implementasi ini, pembatalan B tidak menyisakan report A sebagai hasil B.

Controller memakai lock untuk perubahan state dan nomor pekerjaan `_job_id`. Setiap worker hanya boleh menerbitkan hasil untuk pekerjaan yang masih sesuai. Event terminal dimasukkan ke queue setelah state publik diperbarui, sehingga GUI yang menerima `complete` sudah dapat membaca report yang lengkap.

## 22. Progress harus menunjukkan yang benar-benar diketahui

Sebelum discovery selesai, jumlah kandidat belum diketahui. Menampilkan persentase pada tahap itu dapat memberi kepastian palsu. `ScanProgress` memakai `total=None` untuk tahap yang belum mempunyai total, serta field yang berbeda untuk jumlah item dan byte payload:

```python
@dataclass(frozen=True)
class ScanProgress:
    phase: str
    processed: int
    total: int | None
    source_path: str | None = None
    bytes_processed: int = 0
    bytes_total: int | None = None
```

`frozen=True` menjaga isi satu notifikasi tidak berubah setelah dikirim. Pada scan terkontrol, discovery mengumpulkan kandidat lebih dulu agar total pemrosesan mencakup metadata dan orphan yang benar-benar akan diproses. Payload yang sudah terwakili oleh metadata tidak dihitung lagi sebagai orphan.

Persentase byte untuk satu payload berbeda dari persentase seluruh analisis. Dua file yang sudah selesai dari sepuluh file juga tidak berarti 20% byte sudah dibaca karena ukuran payload dapat berbeda. UI harus mempertahankan perbedaan arti itu.

## 23. Pembatalan kooperatif dan hasil yang tidak lengkap

`ScanControl.cancel()` mengatur sebuah `threading.Event`. Scanner memanggil `check()` pada checkpoint. Ketika sinyal aktif, `check()` melempar `ScanCancelled`, yang berada di luar jenis exception error artefak biasa.

Pemisahan exception ini penting. Kalau pembatalan ditangkap sebagai `source_unreadable` untuk satu file lalu scan berlanjut, tombol Batalkan tidak melakukan yang diminta. Hash parsial juga tidak boleh diterbitkan sebagai hash penuh. Run yang dibatalkan tidak mengembalikan completed report dan controller menonaktifkan ekspornya.

Konteks kontrol aktif dibawa dengan `ContextVar`, sehingga helper discovery dan hashing bisa memeriksa sinyal tanpa memakai satu variabel global yang dibagikan semua thread. Dua pekerjaan yang berjalan pada thread berbeda tidak boleh membatalkan satu sama lain. Kode tetap mengembalikan konteks sebelumnya ketika scan selesai atau melempar exception.

Pembatalan tidak menghentikan thread secara paksa. Membunuh thread di tengah I/O atau pembaruan state dapat meninggalkan kondisi yang tidak jelas. Checkpoint bekerja setelah operasi yang sedang berjalan memberi kontrol kembali. Karena itu GUI dapat menampilkan permintaan pembatalan lebih dahulu, lalu konfirmasi `cancelled` ketika worker benar-benar berhenti.

## 24. Satu penulis laporan dan paket Windows yang bisa diuji

`output.py` memusatkan pemeriksaan tujuan dan penulisan laporan. CLI dan GUI sama-sama menolak file yang sudah ada, tujuan di dalam direktori bukti, serta komponen redirect. Penulisan exclusive dengan `x`, flush, dan `fsync` tidak perlu diimplementasikan ulang oleh setiap antarmuka.

Paket Windows memakai PyInstaller mode `onedir`. Hasilnya folder yang berisi executable dan runtime pendukung, lalu diarsipkan menjadi ZIP versi tertentu. Pengguna mengekstrak seluruh folder; hanya menyalin executable akan menghilangkan runtime pendukung.

Script [`tools/build_windows.py`](../tools/build_windows.py) dijalankan pada Windows x64 asli. Ia menyertakan data zona waktu dan metadata versi, menjalankan startup smoke test pada executable hasil build, lalu membuat ZIP dan checksum. `BUILD-INFO.json` di dalam aplikasi mencatat informasi build dan hasil smoke test.

Smoke test paket menjawab apakah executable beserta Tcl/Tk dan engine berhasil dimulai di lingkungan build. Ia tidak menggantikan unit test, pengujian GUI interaktif, atau validasi artefak Windows asli. Untuk memakai aplikasi, ikuti [panduan desktop](DESKTOP.md). Untuk menjelaskan proyek, bedakan ketiga pertanyaan itu dengan jelas.

## 25. Ruang baca: tabel luas dan detail yang terstruktur

Versi 1.2 memisahkan pekerjaan memilih record dari pekerjaan membaca semua field-nya. Tabel berada di atas dan detail di bawah, memakai lebar ruang hasil. Pembatas horizontal dapat ditarik untuk memberi ruang lebih besar ke bagian yang sedang dibutuhkan. Ringkasan scan dibuat ringkas, sedangkan filter lanjutan bisa dilipat. Nilai filter tetap tersimpan dalam sesi dan selection tetap berlaku ketika kontrolnya disembunyikan.

Perubahan ini menyelesaikan masalah praktis: path Windows dan SHA-256 sering panjang, sedangkan panel sempit hanya memperlihatkan sedikit field sebelum pengguna harus menggulir. Menambah jumlah field dalam panel yang sama tidak menambah informasi yang benar-benar bisa dibaca. Layout perlu memberi prioritas kepada tabel dan detail tanpa menyembunyikan error atau arti scope scan.

[`detail_view.py`](../src/rbinforensics/detail_view.py) memusatkan penyajian satu record melalui `DetailView`. Metode `set_record()` menerima record terpilih, lalu mengisi kelompok **Ringkasan**, **Metadata**, **Payload**, dan **Hash & sumber**. Teks bukti dipresentasikan lewat escaping karakter kontrol agar nama atau path tidak menyamar sebagai struktur antarmuka. Nilai mentah di report tidak diubah oleh pemformatan tampilan.

Ada dua status yang harus dibedakan:

```text
Metadata : Berhasil dibaca
Payload  : Tidak ditemukan
```

Keduanya dapat berlaku sekaligus. `record.status == "ok"` menunjukkan tidak ada masalah pada pemrosesan record itu, tetapi keadaan payload mempunyai field tersendiri. Menampilkan satu kata `ok` tanpa konteks bisa membuat pengguna mengira konten tersedia. Panel baru menjelaskan keadaan metadata dan payload secara terpisah, serta mempertahankan issue yang perlu ditinjau.

Ukuran juga perlu label yang tepat: `original_size` berasal dari `$I`; ukuran sumber metadata adalah jumlah byte file `$I`; ukuran payload adalah pengamatan atas `$R` reguler. Pada orphan, sumber record-nya adalah payload yang diamati sehingga ukuran/hash sumber tidak boleh disebut hash metadata. Penyajian yang rapi tetap harus mempertahankan perbedaan makna tersebut.

## 26. Jendela detail dan hubungan dengan pilihan baris

**Perbesar detail** membuka jendela Tk `Toplevel` yang dapat diubah ukurannya atau dimaksimalkan. Ia memakai `DetailView` yang sama dengan panel bawah. Karena formatter dan labelnya sama, perbaikan pada satu tempat langsung berlaku pada kedua tampilan.

Jendela tambahan tetap menjadi bagian dari event loop Tk yang sama; ia tidak membuat worker parser kedua atau memulai scan baru. Ketika pengguna memilih record lain, kedua tampilan mengikuti pilihan itu. Ketika halaman, hasil filter, atau scan baru membuat pilihan sebelumnya tidak lagi berlaku, detail harus dikosongkan. Menyimpan teks record lama di jendela yang masih terbuka dapat membuat pengguna mengaitkan hash atau timestamp yang salah dengan baris saat ini.

Pengosongan itu juga berlaku pada aksi salin. Tombol tidak boleh tetap menyalin hash record yang sudah tidak terlihat. Sebaliknya, perubahan ukuran teks tidak mengubah pilihan record: ia hanya mengubah cara nilai yang sama digambar. Perbedaan ini merupakan kontrak interaksi yang perlu diuji, bukan sekadar pilihan tampilan.

## 27. Sorting harus membandingkan nilai bukti, lalu membagi halaman

[`presentation.py`](../src/rbinforensics/presentation.py) menyediakan `sort_records()` agar pengurutan tabel tidak menyatu dengan widget Tk. Fungsi menerima daftar record dan menghasilkan urutan tampilan baru tanpa memodifikasi report baseline.

Urutannya harus seperti ini:

```text
baseline lengkap -> selection -> sort seluruh view -> ambil halaman -> render baris
```

Kalau hanya 200 baris pada halaman pertama yang diurutkan, file terbesar pada halaman kedua tidak pernah bisa pindah ke atas. Hasilnya terlihat terurut tetapi tidak benar untuk seluruh view.

Kolom ukuran dibandingkan sebagai integer, bukan teks. Secara leksikal, `"100"` dapat berada sebelum `"20"`, padahal urutan numeriknya terbalik. FILETIME juga harus dibandingkan sebagai raw tick; dua kejadian yang terpisah 100 ns dapat mempunyai tampilan mikrodetik yang sama setelah pembulatan. Python menyimpan integer uint64 ini secara tepat tanpa mengubahnya menjadi float.

Nilai yang diketahui dan tidak diketahui dipisahkan. Ukuran `0` adalah nilai yang diketahui. Metadata tanpa deletion time valid serta orphan tanpa timestamp tetap berada di bagian tidak diketahui, dan tidak diberi tanggal dari filesystem payload. Nilai tidak diketahui ditempatkan di akhir pada arah naik maupun turun.

Klik judul kolom mengubah urutan tabel, bukan `records`, `selection`, atau timeline analitis di JSON. Pengguna dapat mengurutkan tampilan Timeline menurut nama; untuk kembali melihat kronologi, pilih kolom waktu dalam arah naik. Ekspor tetap memakai kontrak renderer/report yang sama, sehingga mengubah urutan visual tidak diam-diam mengubah urutan audit yang disimpan.

## 28. Ukuran teks dan validasi GUI

Pengaturan teks desktop mempunyai batas 9–16 point dengan ukuran awal 11. Ia memperbarui font, tinggi baris, dan widget detail, termasuk jendela detail yang sedang terbuka. Kontrol ini tidak mengubah ukuran file bukti, isi metadata, hasil hashing, atau opsi analisis.

Perubahan font perlu diuji sambil sebuah baris dipilih dan filter aktif. Pilihan, nilai filter, dan hash yang ditampilkan harus tetap menunjuk record yang sama. Layout juga perlu diperiksa pada jendela kecil, filter terbuka/tertutup, serta pembatas yang digeser agar progress, pembatalan, dan ekspor tetap dapat digunakan.

Pengujian GUI bukan hanya memastikan sebuah jendela muncul. Skenario yang relevan mencakup pembacaan path panjang/Unicode, salin nilai yang benar, perubahan pilihan pada jendela detail, sorting lintas halaman dan batas uint64, serta data tanpa timestamp. Pengujian tersebut melengkapi parser/controller tests dan validasi artefak Windows; masing-masing menjawab jenis pertanyaan yang berbeda.
