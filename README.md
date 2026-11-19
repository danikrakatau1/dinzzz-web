# dinzzz — Monitoring Keuangan

Web monitoring keuangan pribadi di **https://dinzzz.my.id**

## Arsitektur

- **Cloudflare Worker** (`worker.js`) — satu file: halaman dashboard, halaman
  `/detail-transaksi`, API, dan login.
- **Cloudflare D1** (`dinzzz-db`) — database untuk data teks transaksi
  (jumlah, sumber/tujuan, kategori, dompet, tanggal, catatan) + alamat foto
  bukti. Foto TIDAK disimpan di dalam database.
- **Cloudflare KV** (`dinzzz-photos`) — penyimpanan file foto bukti transfer,
  terpisah dari database. (R2 belum aktif di akun, jadi foto memakai KV —
  fungsinya sama untuk kebutuhan ini.)
- **Login** — password dibuat sendiri oleh pemilik saat pertama kali membuka
  situs (tersimpan sebagai hash PBKDF2 di D1), sesi memakai cookie bertanda
  tangan HMAC (`SESSION_SECRET`).

## Fitur

- Kartu Saldo Total (semua waktu) + saldo berjalan di tiap transaksi.
- Dashboard: periode Kemarin / Hari ini / Bulan ini, grafik arus kas,
  pengeluaran per kategori, 10 transaksi terakhir.
- Halaman detail: filter ala dashboard iklan (chip cepat, pilih bulan,
  kalender rentang tanggal), klik transaksi untuk detail + foto bukti.
- Catat masuk/keluar dengan foto bukti opsional — foto otomatis dikompres
  di browser (maks 1280px, JPEG 0,72) sebelum diunggah.

## Deploy

Worker di-deploy lewat Cloudflare API (upload script + bindings D1/KV +
secret). Route: `dinzzz.my.id/*` → worker `dinzzz`.
