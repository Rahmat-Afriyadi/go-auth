# Golang Gin Auth Backend

Project backend autentikasi menggunakan **Go (Golang)**, **Gin Web Framework**, **PostgreSQL**, dan **GORM** dengan **Clean / Layered Architecture**.

## Fitur Utama
- **Register & Login**: Hashing password dengan `bcrypt` dan validasi request payload.
- **JWT Access Token & Refresh Token Rotation**: Token akses berdurasi singkat + refresh token yang tersimpan di database dan dapat di-revoke (saat refresh atau logout).
- **Protected Endpoint & Middleware**: Validasi Bearer token (`GET /api/v1/auth/me`).
- **Role-Based Access Control (RBAC)**: Otorisasi berbasis role (`user` & `admin`) melalui middleware `RequireRoles`.
- **Auto-Migration**: Skema tabel `users` dan `refresh_tokens` otomatis dimigrasi saat aplikasi berjalan.

## Struktur Folder
```text
.
├── cmd/
│   └── api/
│       └── main.go                    # Entrypoint aplikasi
├── internal/
│   ├── config/
│   │   └── config.go                  # Konfigurasi environment (.env)
│   ├── database/
│   │   └── postgres.go                # Koneksi PostgreSQL & AutoMigrate GORM
│   ├── dto/
│   │   └── auth_dto.go                # Data Transfer Objects (Request & Response)
│   ├── handlers/
│   │   └── auth_handler.go            # HTTP Handler (Gin)
│   ├── middleware/
│   │   └── auth_middleware.go         # JWT Auth & RBAC Middleware
│   ├── models/
│   │   └── user.go                    # Model GORM (User & RefreshToken)
│   ├── repositories/
│   │   └── user_repository.go         # Layer akses database
│   ├── routes/
│   │   └── routes.go                  # Definisi routing & CORS
│   ├── services/
│   │   └── auth_service.go            # Business logic autentikasi
│   └── utils/
│       ├── jwt.go                     # Helper pembuatan & validasi JWT
│       ├── password.go                # Helper bcrypt hash
│       └── response.go                # Standarisasi format response JSON
├── .env.example                       # Contoh konfigurasi environment
├── docker-compose.yml                 # Setup PostgreSQL dengan Docker
└── go.mod
```

## Cara Menjalankan Project

### 1. Persiapkan Database PostgreSQL
Kamu bisa menggunakan PostgreSQL lokal atau menjalankannya via Docker:
```bash
docker compose up -d
```
Atau sesuaikan kredensial PostgreSQL lokalmu di file `.env`.

### 2. Jalankan Server

**Menggunakan Air (Hot Reload / Realtime Running):**
```bash
air
```

**Atau menggunakan Go standar:**
```bash
go run ./cmd/api/main.go
```
Server akan berjalan di `http://localhost:8080`.

---

## Daftar Endpoint API

| Method | Endpoint | Akses | Deskripsi |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Cek status server |
| `POST` | `/api/v1/auth/register` | Public | Registrasi user baru |
| `POST` | `/api/v1/auth/login` | Public | Login & dapatkan Access + Refresh Token |
| `POST` | `/api/v1/auth/refresh` | Public | Tukar Refresh Token dengan pasangan token baru |
| `POST` | `/api/v1/auth/logout` | Public | Revoke Refresh Token |
| `GET` | `/api/v1/auth/me` | Protected (`Bearer`) | Ambil profil user yang sedang login |
| `GET` | `/api/v1/admin/users` | Admin Only | Ambil daftar semua user |
| `PATCH` | `/api/v1/admin/users/:id/role` | Admin Only | Ubah role user (`user` / `admin`) |
