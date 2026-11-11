# Memahami Recycle Bin Forensics dari byte sampai laporan

Panduan ini menjelaskan proyek yang ada di repository ini: masalah yang diselesaikan, teknologi yang digunakan, kode yang menentukan hasil, dan cara menafsirkan temuan. Contoh path, pengguna, dan kasus di sini fiktif.

## 1. Apa yang sebenarnya kita buat?

Kita membuat **parser artefak forensik dan alat triase lewat terminal**. Input-nya file metadata `$I` atau folder hasil akuisisi yang mengandung file-file tersebut. Output-nya informasi yang bisa diperiksa manusia dan diproses alat lain.

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
temukan kandidat $I secara deterministik
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
render table / JSON / CSV + exit code
```

Empat modul utama memisahkan tanggung jawab:

- [`parser.py`](../src/rbinforensics/parser.py): mengubah `bytes` menjadi nilai metadata; tidak mengakses filesystem.
- [`scanner.py`](../src/rbinforensics/scanner.py): menemukan dan membaca artefak, menghitung hash, serta memeriksa payload.
- [`reports.py`](../src/rbinforensics/reports.py): menyajikan hasil tanpa mengubah cara byte ditafsirkan.
- [`cli.py`](../src/rbinforensics/cli.py): memvalidasi argumen dan menghubungkan komponen menjadi command.

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

`lstat()` memeriksa objek path tanpa mengikuti link terakhir. Setelah file dibuka, `fstat()` memeriksa objek yang benar-benar dibuka. Scanner membandingkan identitas perangkat/inode, ukuran, mtime, dan ctime sebelum, selama, dan sesudah pembacaan. Pada platform yang mendukungnya, flag `O_NOFOLLOW` ikut menolak link terakhir dan `O_NONBLOCK` mencegah pergantian menjadi FIFO membuat proses menunggu tanpa batas.

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
- `2`: pemakaian/konfigurasi salah, kegagalan input/output tingkat run, atau tidak ada kandidat metadata.
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
