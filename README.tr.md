<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <b>Türkçe</b> · <a href="README.ar.md">العربية</a></p>
<p align="center">Video eğitimleri: <a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# PWF Auth Yerel C++ Masaüstü Örneği

Yerel C++17 ile yazılmış, İngilizce arayüzlü bir Windows masaüstü istemcisidir. C# ve Python örnekleriyle aynı lisans akışını izler:

- şifreli lisans girişi ve donanım kimliği (HWID) bağlama;
- sunucunun oturumu sonlandırabildiği canlı düzenli kontrol (heartbeat), yani uzaktan durdurma (kill switch);
- lisansı yeni bir bilgisayara taşıma;
- eksiksiz lisans özeti, yanıtın düzleştirilmiş tablosu ve ham JSON;
- sunucudaki oturumu serbest bırakan açık bir çıkış işlemi

![Giriş yaptıktan sonraki ana ekran](docs/dashboard.png)

PWF Auth sitesi bir C++ paketi yayımlamıyor. Bu nedenle bu örnek, belgelenmiş protokolü doğrudan Windows API'leriyle uygular:

- HTTPS için WinHTTP;
- SHA-256, AES-256-CBC, HMAC-SHA256 ve güvenli IV üretimi için Windows CNG;
- donanım kimliği olarak Windows şifreleme ayarlarındaki `MachineGuid` (.NET, Python ve Node paketlerinin kullandığı değerin aynısıdır, böylece bir bilgisayar tek cihaz sayılır);
- dahil edilen vcpkg manifesti üzerinden otomatik olarak geri yüklenen `nlohmann-json`

`PwfClient.h` / `PwfClient.cpp` yeniden kullanılabilir kısımdır: bunları kendi uygulamanıza kopyalayın

## Neler gösteriliyor

- **Lisans anahtarıyla giriş.** `Login`, anahtarı bu bilgisayara bağlar. Ardından ana ekran anahtarın durumunu, türünü, bitiş tarihini ve kalan süresini, anahtarı kimin sattığını ve yanıttaki tüm alanları gösterir
- **Uzaktan durdurma.** `StartHeartbeat` girişten sonra çalışır. Anahtarı panelinizde yasakladığınızda, duraklattığınızda veya sıfırladığınızda ya da süresi dolduğunda istemci oturum sonu geri çağrısını çalıştırır ve uygulama nedeniyle birlikte giriş sayfasına döner
  - Yalnızca şifreli bir yanıt geçerli cevap sayılır. Art arda üç heartbeat cevapsız kalırsa oturum `NETWORK_LOST` ile, sunucu bu bilgisayarın saatini reddetmeye devam ettiyse `CLOCK_SKEW` ile sona erer. Bu yüzden bilgisayarın saatiyle oynamak yasaklanmış bir anahtarı çalışır durumda tutamaz
  - HTTP 429 için ayrı ve daha geniş bir sınır (10 heartbeat) vardır, çünkü paylaşılan IP adresleri haklı nedenlerle hız sınırına takılabilir
- **Yanlış saat kendiliğinden düzelir.** Sunucu, bilgisayarın saati beş dakikadan fazla saptığı için bir isteği reddettiğinde kendi saatini gönderir. İstemci zaman damgalarını aradaki fark kadar kaydırır ve isteği bir kez daha gönderir
- **Lisansı yeni bir bilgisayara taşıma.** Anahtar başka bir bilgisayara bağlıysa (`HWID_MISMATCH` veya `DEVICE_LIMIT`), giriş sayfası **Move this license to this PC** seçeneğini sunar. Bu seçenek `ResetHardwareId` kullanır ve ardından yeniden giriş yapar. İki taşıma arasında geliştiricinin belirlediği bekleme süresi uygulanır (varsayılan olarak 12 saat)

  ![Move this license to this PC](docs/move-license.png)

- **Bağımsız sunucu doğrulaması.** Her yanıt, tam olarak bu isteğe bağlı geçerli bir sunucu RSA imzası taşımak zorundadır. Uygulama gizli anahtarını (app secret) bilmek bu imzayı taklit etmeye yetmez. İmzasız, değiştirilmiş veya tekrar oynatılmış yanıtlar ayrıştırılmadan önce reddedilir
- **Anlaşılır hatalar**: bağlantı yokken (`PwfNetworkError`), uygulama gizli anahtarı reddedildiğinde (HTTP 401) ve API'nin JSON'u olmayan bir yanıt geldiğinde (`PwfHttpError`)

## Yapılandırma

`main.cpp` dosyasının başındaki yer tutucuyu değiştirin:

```cpp
constexpr char APP_SECRET[] = "YOUR_64_CHARACTER_APP_SECRET";
```

Çalışma zamanında ortam değişkenleriyle ayar geçersiz kılma, tüm derleme yapılandırmalarında devre dışıdır. İstemci yalnızca `https://pwfauth.com` adresini kullanır, kurucuya verilen başka kaynakları reddeder ve hiçbir yönlendirmeyi izlemez. Uygulama gizli anahtarını derleme sırasında ayarlayın; gerçek bir gizli anahtarı asla depoya göndermeyin

`ServerPublicKey.h`, eşleşen sunucu kurulumu için sabitlenmiş (pinned) genel doğrulama anahtarını içerir. PwfClient'ı başka bir projeye kopyalarken bu dosyayı ve `ProductionPolicy.h` dosyasını da ekleyin. Eşleşen sunucu imzalama desteği pwfauth.com üzerinde yayında. Özel imzalama anahtarı sunucuda kalır ve bu istemciyle birlikte asla dağıtılmaz

## Derleme ve çalıştırma

`PWFAuthCpp.slnx` dosyasını Visual Studio'da açın, `Debug | x64` seçin ve `F5` tuşuna basın. Proje, vcpkg bağımlılığını ilk derlemede yerel olarak geri yükler

Çalıştırılabilir dosya şu konuma yazılır:

```text
bin\Debug\PWFAuthCpp.exe
```

Uygulama, giriş penceresini göstermeden önce çevrimdışı bir AES/HMAC gidiş-dönüş öz testi çalıştırır. Gerçek bir giriş için yine de uygulama gizli anahtarı ve geçerli bir anahtar gerekir

## Engellenen ağlar: 2026-10-13 (1.4)

Bazı ağlar `pwfauth.com` adını engelliyor (BAE'deki Etisalat "böyle bir alan adı yok" yanıtı veriyor), bu yüzden uygulama VPN olmadan lisans sunucusuna ulaşamıyordu. `PwfClient` artık `pwfauth.com` hiç yanıt vermediğinde aynı sunucuyu ikinci bir adla, `https://pwfauth.net` üzerinden dener:

- yalnızca isteğin hiçbir sunucuya ulaşmadığı kesinse (ad çözümlenemiyor, bağlantı yok, güvenli bağlantı reddediliyor) ya da bu istemci daha önce hiç yanıt almamışken zaman aşımı olursa;
- bir yanıt, hata yanıtı bile olsa, asla diğer ada gönderilmez;
- `pwfauth.net` bir kez yanıt verdiğinde istemci kapanana kadar onu kullanmaya devam eder;
- iki ad da `ProductionPolicy.h` içinde sabittir; sunucu, imzalama anahtarı ve tüm yanıt kontrolleri aynıdır

Yeni `PwfClient.cpp`, `PwfClient.h` ve `ProductionPolicy.h` dosyalarını uygulamanıza kopyalayıp yeniden derleyin. Başka hiçbir şey değişmiyor

## Kopan bağlantılar: 2026-10-12 (1.3.1)

Bir istek hiç yanıt almadığında (genellikle bağlantı yolda kapanmıştır, Windows hatası 10054 veya WinHTTP hatası 12030), `PwfClient` artık aynı isteği 300 ms sonra yeni bir bağlantı üzerinden bir kez daha gönderir. Önceden böyle bir çağrı `PwfNetworkError` ile, "Cannot reach the license server" mesajıyla başarısız oluyordu. Yalnızca bu durumda yeniden denenir: bir yanıt (hata yanıtı bile), okunurken kopan bir yanıt ve zaman aşımı asla iki kez gönderilmez. Başka bir şey değişmedi: imzalama anahtarı ve fonksiyonlar aynı

## Müşteri hesapları: 2026-10-12 (1.3)

Lisans anahtarlarının yanı sıra müşterileriniz kullanıcı adı ve parolası olan bir hesaba sahip olabilir (uygulama için müşteri hesaplarını panelden açın). `PwfClient` artık şunları içeriyor:

| Fonksiyon | Ne yapar |
|---|---|
| `RegisterAccount(username, password, email)` | Bir hesap oluşturur |
| `RegisterAccountWithKey(username, password, key, email)` | Bir anahtarın süresini alan bir hesap oluşturur (anahtar tükenir) |
| `AccountLogin(username, password)` | Hesabın bu bilgisayarda oturum açmasını sağlar; ardından `Login` sonrasında olduğu gibi heartbeat'i başlatın |
| `ChangeAccountPassword(username, current, new)` | Parolayı değiştirir (hesabın tüm oturumları kapatılır) |
| `RedeemKey(username, password, key)` / `RedeemKey(key)` | Bir anahtarın süresini hesaba ekler (ikincisi açık olan oturumu kullanır) |

```cpp
PwfClient client(appSecret);

PwfResponse made = client.RegisterAccount("alice", "a-strong-password", "alice@example.com");
if (!made.Success() && made.ErrorCode() != "USERNAME_EXISTS")
    return ShowError(made.Message());          // written for the customer

PwfResponse login = client.AccountLogin("alice", "a-strong-password");
if (!login.Success())
    return ShowError(login.Message());         // INVALID_CREDENTIALS, BANNED, EXPIRED, ...

client.SetSessionEndedCallback([](const std::string& code, const std::string& message) {
    // banned, paused, expired, signed out from the panel: close your app here
});
client.StartHeartbeat();

// later: a key bought from a reseller adds its time to the account
PwfResponse added = client.RedeemKey("XXXXX-XXXXX-XXXXX-XXXXX");
```

Yeni `PwfClient.h` ve `PwfClient.cpp` dosyalarını projenize kopyalayın; `ServerPublicKey.h` ve `ProductionPolicy.h`, 1.2 sürümünden bu yana değişmedi

## Yeni sunucu anahtarı: 2026-10-11 (1.2)

PWF Auth yanıtlarını yeni bir anahtarla imzalıyor. Yeni `ServerPublicKey.h` dosyasını (ve `PwfClient.cpp` dosyasını) projenize kopyalayıp yeniden derleyin: eski anahtarla derlenmiş bir sürüm, mevcut sunucudan gelen her yanıtı reddeder

## Güvenlik güncellemesi: 2026-10-09

Bu örneğin eski bir sürümünü içeren uygulamaları yeniden derleyip yeniden dağıtın. Mevcut EXE dosyaları bu korumayı kendiliğinden kazanmaz. PWFAUTH_BASE_URL ve PWFAUTH_SECRET ortam değişkenleriyle geçersiz kılma artık Debug'da da Release'te de desteklenmiyor. Yeniden kullanılabilir istemci yalnızca üretim HTTPS kaynağını kabul eder ve yönlendirmeleri devre dışı bırakır

Her HTTP isteği yeni bir 256 bitlik nonce içerir. İstemci, bir yanıtı ayrıştırmadan önce sabitlenmiş genel anahtarıyla RSA-3072 / PKCS#1 v1.5 / SHA-256 imzasını doğrular. İmzalanan döküm; nonce'u, metodu, uç noktayı, istek gövdesinin özetini, yanıt durumunu ve yanıt gövdesinin özetini birbirine bağlar. AES/HMAC doğrulaması da yerinde kalır. İmzasız proxy veya CDN hataları da reddedilir ve doğrulama hatası olarak görünebilir

Doğrulama kapsamında Release x64 derlemesi, PHP ile Windows CNG arasında birlikte çalışabilirlik, değiştirilmiş ve tekrar oynatılmış yanıtların reddedilmesi ve üretim ortamında HTTPS üzerinden geçerli ve geçersiz sentetik lisanslarla gerçek giriş, heartbeat ve çıkış test edildi. Orijinal istemci, bildirilen yerel emülatörden gelen geçersiz bir anahtarı kabul ediyordu; güncellenmiş istemci emülatörün ortam değişkeni geçersiz kılmasını yok saydı ve ona hiçbir istek göndermedi

Bu güncelleme bildirilen yönlendirme/emülasyon yolunu kapatır. Ancak kendi kontrolündeki bir bilgisayarda çalıştırılabilir dosyanın kendisini değiştiren bir saldırgana karşı direnç garanti etmez
