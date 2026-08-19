/**
 * Portal Carian id-Delima SK Seksyen 24
 * Backend Controller & Security Layer
 *
 * Mengendalikan carian data murid, pengesahan identiti MOEIS ID,
 * keselamatan kata laluan, kawalan had kadar, dan penghantaran emel permohonan reset.
 */

// Konfigurasi Asas Sistem
var CONFIG = {
  DEFAULT_ADMIN_EMAIL: "sekolah-9593@moe-dl.edu.my",
  MAX_SEARCH_RESULTS: 20,
  MIN_QUERY_LENGTH: 3,
  SEARCH_RATE_LIMIT: 25,             // Maksimum 25 carian per 60 saat per token
  RESET_RATE_LIMIT_SESSION: 3,       // Maksimum 3 permohonan reset per 300 saat (5 minit) per sesi
  RESET_RATE_LIMIT_STUDENT: 2,       // Maksimum 2 permohonan reset per 900 saat (15 minit) per murid
  PASSWORD_VERIFY_LOCK_LIMIT: 5,     // Maksimum 5 percubaan pengesahan gagal sebelum sekatan akaun
  PASSWORD_VERIFY_LOCK_WINDOW: 600,  // 10 minit tetingkap sekatan keselamatan (600 saat)
  PASSWORD_VERIFY_TOKEN_LIMIT: 15,   // Maksimum 15 percubaan pengesahan per 60 saat per token
  LOG_SHEET_NAME: "Log_Permohonan_Reset"
};

/**
 * Endpoint utama Web App
 * Dilindungi daripada Clickjacking / UI Redressing dengan XFrameOptionsMode.DEFAULT
 */
function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('Carian id-Delima SK Seksyen 24')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
}

/* ==========================================================================
   FUNGSI PERSENDIRIAN / KESELAMATAN (PRIVATE HELPER FUNCTIONS)
   Semua fungsi dalaman menggunakan akhiran '_' bagi mengelakkan capaian
   terus tanpa kebenaran melalui google.script.run dari klien web.
   ========================================================================== */

/**
 * Mendapatkan emel admin secara dinamik daripada Script Properties
 * atau menggunakan nilai lalai jika belum dikonfigurasikan.
 */
function getAdminEmail_() {
  try {
    var customEmail = PropertiesService.getScriptProperties().getProperty("ADMIN_EMAIL");
    if (customEmail && customEmail.trim().indexOf("@") !== -1) {
      return customEmail.trim();
    }
  } catch (e) {
    console.warn("Ralat membaca Script Properties: " + e.message);
  }
  return CONFIG.DEFAULT_ADMIN_EMAIL;
}

/**
 * Pembantu kawalan had kadar (Rate Limiting) menggunakan CacheService
 */
function checkRateLimit_(key, limit, windowSeconds) {
  try {
    var cache = CacheService.getScriptCache();
    var currentCount = cache.get(key);
    var count = currentCount ? parseInt(currentCount, 10) : 0;
    
    if (count >= limit) {
      return false; // Melebihi had
    }
    
    cache.put(key, (count + 1).toString(), windowSeconds);
    return true;
  } catch (e) {
    console.warn("Ralat semakan had kadar cache: " + e.message);
    return true; // Teruskan jika cache gagal
  }
}

/**
 * Membersihkan input rentetan daripada aksara kawalan dan tag HTML berbahaya
 */
function sanitizeInput_(str, maxLen) {
  if (typeof str !== 'string') return '';
  var cleaned = str.replace(/[\r\n\t\x00-\x1F\x7F]/g, ' ')
                   .replace(/<[^>]*>/g, '')
                   .trim();
  return cleaned.substring(0, maxLen || 100);
}

/**
 * Escape aksara khas untuk paparan HTML selamat bagi mengelakkan XSS & Injection
 */
function escapeHtml_(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Menyahaktifkan Formula Injection (CSV / Spreadsheet Injection) dalam Google Sheets.
 * Jika teks bermula dengan '=', '+', '-', '@', tab, atau newline,
 * ia diprefiks dengan tanda petik tunggal (') agar Google Sheets merawatnya sebagai teks biasa.
 */
function sanitizeForSheet_(value) {
  if (value === null || value === undefined) return '';
  var str = String(value).trim();
  if (str.length > 0 && /^[=+\-@\t\r]/.test(str)) {
    return "'" + str;
  }
  return str;
}

/**
 * Menormalkan tajuk lajur (Header) daripada spreadsheet:
 * - Menukar kepada rentetan (string)
 * - Menghapuskan tab / aksara ruang tambahan (\t, \r, \n)
 * - Menggabungkan whitespace berlebihan
 * - Memotong (trim) ruang di awal dan akhir
 * - Menukar kepada huruf besar (UPPERCASE)
 */
function normalizeHeader_(h) {
  if (h === null || h === undefined) return '';
  return String(h)
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ')
    .toUpperCase();
}

/**
 * Mengesan kedudukan indeks lajur secara dinamik berdasarkan tajuk lajur spreadsheet.
 * Menggunakan padanan tepat (exact matching) untuk mengelakkan kekeliruan antara:
 * - KELAS
 * - KOD KELAS
 * - ALIRAN KELAS
 * - BIDANG KELAS
 */
function getHeaderMapping_(headers) {
  var colMap = {
    delimaId: -1,
    name: -1,
    moeisId: -1,
    kelas: -1,
    aliran: -1,
    password: -1,
    status: -1
  };

  if (!headers || !headers.length) return colMap;

  for (var c = 0; c < headers.length; c++) {
    var norm = normalizeHeader_(headers[c]);
    
    if (norm === "ID DELIMA" || norm === "ID-DELIMA" || norm === "ID DELIMa" || norm === "EMEL DELIMA" || norm === "EMAIL") {
      colMap.delimaId = c;
    } else if (norm === "NAMA" || norm === "NAMA MURID") {
      colMap.name = c;
    } else if (norm === "MOEIS ID" || norm === "ID MOEIS" || norm === "MOEIS" || norm === "MOEIS_ID" || norm === "ID_MOEIS" || norm === "NO KP" || norm === "NO. KP" || norm === "NO KAD PENGENALAN" || norm === "NO. KAD PENGENALAN" || norm === "NO IC" || norm === "NO. IC" || norm === "KP" || norm === "IC") {
      colMap.moeisId = c;
    } else if (norm === "ALIRAN KELAS" || norm === "ALIRAN") {
      colMap.aliran = c;
    } else if (norm === "KELAS") {
      colMap.kelas = c;
    } else if (norm === "PASSWORD" || norm === "KATA LALUAN" || norm === "KATALALUAN") {
      colMap.password = c;
    } else if (norm === "STATUS WARGANEGARA" || norm === "STATUS") {
      colMap.status = c;
    }
  }

  return colMap;
}

/**
 * Mengesan sheet data murid yang betul secara selamat (mengabaikan sheet log)
 */
function getStudentDataSheet_(ss) {
  if (!ss) return null;
  var sheets = ss.getSheets();
  if (!sheets || !sheets.length) return null;
  
  // 1. Cari sheet yang mengandungi tajuk lajur murid yang sah
  for (var i = 0; i < sheets.length; i++) {
    var s = sheets[i];
    if (s.getName() === CONFIG.LOG_SHEET_NAME) continue;
    var lastCol = s.getLastColumn();
    if (lastCol < 2) continue;
    var headers = s.getRange(1, 1, 1, lastCol).getValues()[0];
    var colMap = getHeaderMapping_(headers);
    if (colMap.name !== -1 && colMap.delimaId !== -1) {
      return s;
    }
  }
  
  // 2. Fallback kepada sheet aktif jika bukan sheet log
  var active = ss.getActiveSheet();
  if (active && active.getName() !== CONFIG.LOG_SHEET_NAME) {
    return active;
  }
  
  return sheets[0];
}

/**
 * Mengesahkan format carian bagi mengelakkan penuaian data (scraping)
 */
function validateSearchQuery_(query) {
  if (!query || typeof query !== 'string') {
    return { valid: false, message: "Sila masukkan teks carian." };
  }
  
  var cleaned = sanitizeInput_(query, 50);
  if (cleaned.length < CONFIG.MIN_QUERY_LENGTH) {
    return { 
      valid: false, 
      message: "Sila masukkan sekurang-kurangnya " + CONFIG.MIN_QUERY_LENGTH + " aksara untuk carian." 
    };
  }
  
  // Senarai kata yang terlalu umum jika dicari secara bersendirian
  var broadStopWords = ["bin", "binti", "bt", "ibni", "anak", "dan", "tahun", "kelas", "mohd", "muhd", "muhammad", "ahmad", "siti", "nur"];
  var terms = cleaned.toLowerCase().split(/\s+/).filter(function(t) { return t.length > 0; });
  
  if (terms.length === 1 && broadStopWords.indexOf(terms[0]) !== -1) {
    return { 
      valid: false, 
      message: "Carian '" + cleaned + "' terlalu umum. Sila sertakan nama penuh atau kelas (cth: '" + cleaned + " 3 Dedikasi')." 
    };
  }
  
  return { valid: true, cleanedQuery: cleaned, terms: terms };
}

/**
 * Perekodan permohonan reset ke tab lembaran khas untuk rujukan & sandaran admin.
 * Fungsi ini dilindungi dengan sanitasi Formula Injection (sanitizeForSheet_).
 */
function logPasswordResetRequest_(studentName, studentClass, studentEmail, proposedPassword, statusMsg) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) return;
    
    var logSheet = ss.getSheetByName(CONFIG.LOG_SHEET_NAME);
    if (!logSheet) {
      logSheet = ss.insertSheet(CONFIG.LOG_SHEET_NAME);
      logSheet.appendRow(["Tarikh & Masa", "Nama Murid", "Kelas", "ID DELIMa", "Cadangan Kata Laluan Baharu", "Status"]);
      logSheet.getRange(1, 1, 1, 6).setFontWeight("bold").setBackground("#ffd6df");
      logSheet.setFrozenRows(1);
    }
    
    var timestamp = Utilities.formatDate(new Date(), "Asia/Singapore", "yyyy-MM-dd HH:mm:ss");
    logSheet.appendRow([
      sanitizeForSheet_(timestamp),
      sanitizeForSheet_(studentName),
      sanitizeForSheet_(studentClass),
      sanitizeForSheet_(studentEmail || "-"),
      sanitizeForSheet_(proposedPassword || "(Tidak disertakan)"),
      sanitizeForSheet_(statusMsg || "Permohonan Dihantar")
    ]);
  } catch (e) {
    console.error("Gagal merekod log ke Google Sheets: " + e.message);
  }
}

/**
 * Fungsi Pembantu Dalaman untuk Admin menguji penghantaran emel & kebenaran OAuth.
 * Ditandakan sebagai fungsi dalaman (akhiran _) agar tidak boleh disalahguna oleh pelawat awam.
 */
function testAdminNotification_() {
  var adminEmail = getAdminEmail_();
  var timestamp = Utilities.formatDate(new Date(), "Asia/Singapore", "dd-MM-yyyy, hh:mm a");
  var subject = "[Ujian Sistem] Pengesahan Penghantaran Emel id-Delima SK Seksyen 24";
  
  var htmlBody = 
    '<div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; max-width: 500px;">' +
      '<h3 style="color: #ff8fa3; margin-top:0;">Ujian Sambungan Emel Berjaya!</h3>' +
      '<p>Konfigurasi emel portal carian id-Delima SK Seksyen 24 berfungsi dengan sempurna.</p>' +
      '<p><b>Masa Ujian:</b> ' + timestamp + '</p>' +
      '<p><b>Alamat Penerima:</b> ' + adminEmail + '</p>' +
      '<hr style="border:none; border-top:1px solid #eee;">' +
      '<p style="font-size:12px; color:#888;">Ini adalah emel ujian yang dijalankan dari Google Apps Script Editor.</p>' +
    '</div>';

  try {
    MailApp.sendEmail({
      to: adminEmail,
      subject: subject,
      htmlBody: htmlBody,
      body: "Ujian sambungan emel portal carian id-Delima SK Seksyen 24 berjaya dihantar pada " + timestamp + "."
    });
    return "BERJAYA: Emel ujian telah berjaya dihantar ke " + adminEmail;
  } catch (e) {
    return "GAGAL: " + e.toString();
  }
}

/* ==========================================================================
   ENDPOINT AWAM (PUBLIC CLIENT-ACCESSIBLE ENDPOINTS)
   Hanya fungsi-fungsi di bawah yang boleh dipanggil dari pelayar pengguna.
   ========================================================================== */

/**
 * FUNGSI CARIAN MAKLUMAT MURID
 *
 * JAMINAN KESELAMATAN:
 * - MOEIS ID dan PASSWORD TIDAK SEKALI-KALI dipulangkan dalam carian ini.
 * - Tiada padanan separa (substring) pada MOEIS ID untuk mengelakkan serangan deduksi (Oracle Attack).
 * - Carian awam terhad kepada medan terbuka: Nama, Kelas, Aliran, ID DELIMa.
 * - Sekiranya carian adalah nombor MOEIS ID tepat pengguna, padanan HANYA dibuat secara padanan penuh tepat (exact match).
 */
function searchData(query, clientToken) {
  try {
    // 1. Kawalan Had Kadar (Rate Limiting)
    var rateKey = "search_" + (clientToken ? sanitizeInput_(clientToken, 40) : "anon");
    if (!checkRateLimit_(rateKey, CONFIG.SEARCH_RATE_LIMIT, 60)) {
      return { 
        success: false, 
        error: "Terlalu banyak carian dibuat dalam masa singkat. Sila tunggu 1 minit sebelum mencuba lagi." 
      };
    }
    
    // 2. Pengesahan Input Carian
    var validation = validateSearchQuery_(query);
    if (!validation.valid) {
      return { success: false, error: validation.message };
    }
    
    var searchTerms = validation.terms;
    
    // 3. Capaian Pangkalan Data Spreadsheet
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) {
      return { success: false, error: "Pangkalan data spreadsheet tidak ditemui." };
    }
    
    var sheet = getStudentDataSheet_(ss);
    if (!sheet) {
      return { success: false, error: "Lembaran data murid tidak ditemui." };
    }
    
    var data = sheet.getDataRange().getValues();
    if (!data || data.length < 2) {
      return { success: true, data: [], limitReached: false };
    }
    
    // Mengesan kedudukan lajur secara dinamik
    var colMap = getHeaderMapping_(data[0]);
    if (colMap.name === -1 || colMap.delimaId === -1) {
      return { success: false, error: "Struktur lajur spreadsheet tidak lengkap (NAMA / ID DELIMA tidak ditemui)." };
    }
    
    var results = [];
    var maxResults = CONFIG.MAX_SEARCH_RESULTS;
    
    // Gelung bermula dari baris ke-2 (skip header)
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      var namaVal = (colMap.name !== -1 && row[colMap.name]) ? row[colMap.name].toString().trim() : '';
      var delimaVal = (colMap.delimaId !== -1 && row[colMap.delimaId]) ? row[colMap.delimaId].toString().trim() : '';
      var kelasVal = (colMap.kelas !== -1 && row[colMap.kelas]) ? row[colMap.kelas].toString().trim() : '';
      var aliranVal = (colMap.aliran !== -1 && row[colMap.aliran]) ? row[colMap.aliran].toString().trim() : '';
      var moeisVal = (colMap.moeisId !== -1 && row[colMap.moeisId]) ? row[colMap.moeisId].toString().trim() : '';
      
      // Medan teks awam untuk padanan (NAMA, KELAS, ALIRAN, ID DELIMA)
      var publicText = (namaVal + " " + kelasVal + " " + aliranVal + " " + delimaVal).toLowerCase();
      var cleanStoredMoeis = moeisVal.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      
      var isMatch = true;
      for (var j = 0; j < searchTerms.length; j++) {
        var term = searchTerms[j];
        var cleanTerm = term.replace(/[^a-z0-9]/g, '');
        
        // Padanan awam: Substring pada teks awam
        var publicMatched = (publicText.indexOf(term) !== -1);
        
        // Padanan MOEIS ID: HANYA padanan tepat penuh (EXACT FULL MATCH) dengan minimum 4 aksara
        // Mengelakkan deduksi huruf demi huruf (Oracle Attack)
        var exactMoeisMatched = (cleanStoredMoeis.length >= 4 && cleanTerm.length >= 4 && cleanStoredMoeis === cleanTerm);
        
        if (!publicMatched && !exactMoeisMatched) {
          isMatch = false;
          break;
        }
      }
      
      if (isMatch) {
        // HANYA medan selamat yang dipulangkan (TIADA MOEIS ID & TIADA PASSWORD)
        results.push({
          name: sanitizeInput_(namaVal, 100),
          delimaId: sanitizeInput_(delimaVal, 100),
          aliran: sanitizeInput_(aliranVal, 50),
          kelas: sanitizeInput_(kelasVal, 50)
        });
        
        if (results.length >= maxResults) {
          break; 
        }
      }
    }
    
    return { 
      success: true, 
      data: results, 
      limitReached: results.length >= maxResults 
    };
  } catch (error) {
    console.error("Ralat dalam searchData: " + error.toString());
    return { success: false, error: "Ralat sistem semasa memproses carian. Sila cuba sebentar lagi." };
  }
}

/**
 * PENGESAHAN IDENTITI MOEIS ID & PENGAMBILAN KATA LALUAN (SERVER-SIDE)
 *
 * KAWALAN KESELAMATAN DIPERKETATKAN:
 * 1. Sekatan percubaan gagal (Brute Force Lockout) diikat terus kepada akaun murid sasaran
 *    (Bukan sekadar token klien yang boleh ditukar ganti).
 * 2. Selepas 5 percubaan gagal berturut-turut untuk murid tersebut, akaun disekat selama 10 minit.
 * 3. Perbandingan tepat tanpa sensitiviti tanda sempang/ruang.
 * 4. Kata laluan hanya dipulangkan jika padanan sah 100%.
 */
function verifyMoeisAndGetPassword(studentIdentifier, moeisId, clientToken) {
  try {
    // 1. Sanitasi Input
    var sId = sanitizeInput_(studentIdentifier, 100);
    var submittedMoeis = sanitizeInput_(moeisId, 50);
    var token = sanitizeInput_(clientToken, 40);

    if (!sId) {
      return { 
        success: false, 
        verified: false, 
        error: "Maklumat murid tidak sah. Sila buat carian semula." 
      };
    }

    if (!submittedMoeis) {
      return { 
        success: false, 
        verified: false, 
        error: "Sila masukkan MOEIS ID untuk membuat pengesahan." 
      };
    }

    // 2. Kawalan Had Kadar & Perlindungan Brute Force Sasaran Akaun Murid
    var safeIdKey = sId.toLowerCase().replace(/[^a-z0-9]/g, '_');
    var lockKey = "pwd_lock_student_" + safeIdKey;
    var cache = CacheService.getScriptCache();
    
    // Semak jika akaun murid sedang dalam tempoh sekatan keselamatan
    var failedAttemptsStr = cache.get(lockKey);
    var failedAttempts = failedAttemptsStr ? parseInt(failedAttemptsStr, 10) : 0;
    
    if (failedAttempts >= CONFIG.PASSWORD_VERIFY_LOCK_LIMIT) {
      return { 
        success: false, 
        verified: false, 
        error: "Akaun ini telah disekat sementara selama 10 minit kerana melebihi had percubaan pengesahan gagal. Sila hubungi guru penyelaras DELIMa jika anda memerlukan bantuan." 
      };
    }

    // Kawalan had kadar umum per sesi (Anti-Scraping)
    var sessionKey = "pwd_token_" + (token || "anon");
    if (!checkRateLimit_(sessionKey, CONFIG.PASSWORD_VERIFY_TOKEN_LIMIT, 60)) {
      return { 
        success: false, 
        verified: false, 
        error: "Terlalu banyak percubaan pengesahan daripada peranti anda. Sila tunggu sebentar sebelum mencuba lagi." 
      };
    }

    // 3. Capaian Lembaran Pangkalan Data
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) {
      return { success: false, verified: false, error: "Pangkalan data spreadsheet tidak ditemui." };
    }

    var sheet = getStudentDataSheet_(ss);
    if (!sheet) {
      return { success: false, verified: false, error: "Lembaran data murid tidak ditemui." };
    }

    var data = sheet.getDataRange().getValues();
    if (!data || data.length < 2) {
      return { success: false, verified: false, error: "Tiada rekod data murid ditemui." };
    }

    // Mengesan lajur secara dinamik
    var colMap = getHeaderMapping_(data[0]);
    if (colMap.delimaId === -1 || colMap.moeisId === -1 || colMap.password === -1) {
      return { 
        success: false, 
        verified: false, 
        error: "Struktur lajur pangkalan data tidak lengkap. Sila hubungi guru penyelaras DELIMa." 
      };
    }

    // 4. Cari rekod murid yang sepadan berdasarkan ID DELIMa
    var matchedRow = null;
    var targetDelima = sId.trim().toLowerCase();

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      var rowDelima = row[colMap.delimaId] ? String(row[colMap.delimaId]).trim().toLowerCase() : '';
      if (rowDelima === targetDelima) {
        matchedRow = row;
        break;
      }
    }

    if (!matchedRow) {
      return { 
        success: false, 
        verified: false, 
        error: "Rekod murid tidak ditemui dalam sistem. Sila buat carian semula." 
      };
    }

    // 5. Perbandingan MOEIS ID
    var storedMoeis = matchedRow[colMap.moeisId] ? String(matchedRow[colMap.moeisId]).trim() : '';
    var storedPassword = matchedRow[colMap.password] ? String(matchedRow[colMap.password]).trim() : '';

    var cleanSubmittedMoeis = submittedMoeis.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    var cleanStoredMoeis = storedMoeis.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

    if (!cleanStoredMoeis || cleanStoredMoeis.length < 3 || cleanSubmittedMoeis !== cleanStoredMoeis) {
      // Rekodkan percubaan gagal ke dalam cache sekatan murid
      var newFails = failedAttempts + 1;
      cache.put(lockKey, newFails.toString(), CONFIG.PASSWORD_VERIFY_LOCK_WINDOW);
      
      var attemptsLeft = CONFIG.PASSWORD_VERIFY_LOCK_LIMIT - newFails;
      var feedbackMsg = "MOEIS ID tidak sepadan. Sila semak dan cuba lagi.";
      if (attemptsLeft > 0) {
        feedbackMsg += " (" + attemptsLeft + " percubaan lagi sebelum sekatan sementara)";
      } else {
        feedbackMsg = "Had percubaan dicapai. Akaun ini disekat sementara selama 10 minit.";
      }

      return { 
        success: false, 
        verified: false, 
        error: feedbackMsg 
      };
    }

    // 6. Pengesahan Berjaya: Padam rekod percubaan gagal dalam cache
    cache.remove(lockKey);

    if (!storedPassword) {
      return { 
        success: false, 
        verified: true, 
        error: "Kata laluan belum ditetapkan dalam pangkalan data. Sila hubungi guru penyelaras DELIMa." 
      };
    }

    // Pulangkan kata laluan kepada pengguna yang sah
    return { 
      success: true, 
      verified: true, 
      password: storedPassword 
    };

  } catch (error) {
    console.error("Ralat dalam verifyMoeisAndGetPassword: " + error.toString());
    return { 
      success: false, 
      verified: false, 
      error: "Ralat sistem semasa pengesahan. Sila cuba lagi sebentar lagi." 
    };
  }
}

/**
 * Penghantaran Emel Permohonan Reset Kata Laluan dengan perlindungan sekuriti menyeluruh
 */
function sendPasswordResetEmail(payload) {
  try {
    var studentEmail = "";
    var studentName = "";
    var studentClass = "";
    var newPassword = "";
    var clientToken = "";
    var hpField = "";
    var submitTime = 0;

    if (typeof payload === 'object' && payload !== null) {
      studentEmail = payload.studentEmail || "";
      studentName = payload.studentName || "";
      studentClass = payload.studentClass || "";
      newPassword = payload.newPassword || "";
      clientToken = payload.clientToken || "";
      hpField = payload.hpField || "";
      submitTime = Number(payload.submitTime) || 0;
    } else {
      studentEmail = arguments[0] || "";
      studentName = arguments[1] || "";
      studentClass = arguments[2] || "";
      newPassword = arguments[3] || "";
    }

    // 1. Perlindungan Honeypot (Perangkap Bot)
    if (hpField && hpField.trim() !== "") {
      console.warn("Honeypot field triggered. Mengabaikan submission bot.");
      return { success: true, message: "Permohonan telah diproses." };
    }

    // 2. Perlindungan Masa Penghantaran Terlalu Pantas (< 1.2 saat)
    if (submitTime > 0) {
      var timeDiff = Date.now() - submitTime;
      if (timeDiff < 1200) {
        console.warn("Permohonan dihantar terlalu pantas: " + timeDiff + "ms");
        return { success: false, error: "Penghantaran borang terlalu pantas dikesan. Sila cuba semula." };
      }
    }

    // 3. Sanitasi Input
    studentName = sanitizeInput_(studentName, 100);
    studentClass = sanitizeInput_(studentClass, 50);
    studentEmail = sanitizeInput_(studentEmail, 100);
    newPassword = sanitizeInput_(newPassword, 50);

    // 4. Validasi Medan Wajib
    if (!studentName || !studentClass) {
      return { success: false, error: "Sila lengkapkan Nama Penuh Murid dan Kelas." };
    }

    // 5. Kawalan Had Kadar (Rate Limiting Sesi & Murid)
    var sessionKey = "reset_session_" + (clientToken ? sanitizeInput_(clientToken, 40) : "anon");
    if (!checkRateLimit_(sessionKey, CONFIG.RESET_RATE_LIMIT_SESSION, 300)) {
      return { 
        success: false, 
        error: "Had permohonan dicapai untuk peranti anda. Sila tunggu 5 minit sebelum menghantar permohonan baharu." 
      };
    }

    var studentRateKey = "reset_student_" + (studentEmail ? studentEmail.toLowerCase().replace(/[^a-z0-9]/g, '_') : studentName.toLowerCase().replace(/\s+/g, '_'));
    if (!checkRateLimit_(studentRateKey, CONFIG.RESET_RATE_LIMIT_STUDENT, 900)) {
      return { 
        success: false, 
        error: "Permohonan reset untuk murid ini telah dihantar baru-baru ini. Sila beri masa kepada admin untuk memproses permohonan." 
      };
    }

    var adminEmail = getAdminEmail_();
    var timestampStr = Utilities.formatDate(new Date(), "Asia/Singapore", "dd-MM-yyyy, hh:mm a");
    var subject = "[Permohonan Reset Kata Laluan id-Delima] " + studentName + " (" + studentClass + ")";

    var pwdDisplay = (newPassword && newPassword.trim() !== "") 
      ? escapeHtml_(newPassword) 
      : "<em>(Tidak disertakan - Sila tetapkan kata laluan rawak yang selamat)</em>";

    // Format Teks Biasa (Fallback)
    var plainBody = "Salam Sejahtera Penyelaras DELIMa,\n\n" +
      "Satu permohonan untuk reset kata laluan id-Delima telah diterima melalui Portal Carian Murid SK Seksyen 24.\n\n" +
      "--- BUTIRAN MURID ---\n" +
      "Nama Penuh : " + studentName + "\n" +
      "Kelas      : " + studentClass + "\n" +
      "ID DELIMa  : " + (studentEmail ? studentEmail : "Tidak dinyatakan") + "\n" +
      "Cadangan Kata Laluan Baharu: " + (newPassword ? newPassword : "(Tidak disertakan)") + "\n" +
      "Masa Permohonan: " + timestampStr + "\n\n" +
      "Sila semak konsol admin DELIMa / Google Workspace untuk tindakan selanjutnya.\n\n" +
      "- Mesej dijana secara automatik oleh Portal Carian id-Delima SK Seksyen 24";

    // Format Emel HTML Moden & Profesional
    var htmlBody = 
      '<div style="font-family: Arial, Helvetica, sans-serif; background-color: #f7f9fb; padding: 25px; color: #333;">' +
        '<div style="max-width: 550px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.06); border: 1px solid #eaeaea;">' +
          '<div style="background: linear-gradient(135deg, #ff8fa3 0%, #ff6b8b 100%); padding: 20px 25px; color: #ffffff; text-align: center;">' +
            '<h2 style="margin: 0; font-size: 20px; letter-spacing: 0.5px;">Permohonan Reset Kata Laluan id-Delima</h2>' +
            '<p style="margin: 5px 0 0 0; font-size: 13px; opacity: 0.9;">SK Seksyen 24, Shah Alam</p>' +
          '</div>' +
          '<div style="padding: 25px;">' +
            '<p style="font-size: 14px; margin-top: 0; color: #555;">Salam Sejahtera Admin / Guru Penyelaras DELIMa,</p>' +
            '<p style="font-size: 14px; color: #555;">Permohonan baharu telah diterima daripada murid melalui portal carian sekolah:</p>' +
            '<table style="width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #fafbfc; border-radius: 8px; overflow: hidden; border: 1px solid #ebeef2;">' +
              '<tr>' +
                '<td style="padding: 10px 15px; font-weight: bold; width: 35%; border-bottom: 1px solid #ebeef2; color: #666; font-size: 13px;">Nama Penuh</td>' +
                '<td style="padding: 10px 15px; border-bottom: 1px solid #ebeef2; font-weight: bold; color: #222; font-size: 14px;">' + escapeHtml_(studentName) + '</td>' +
              '</tr>' +
              '<tr>' +
                '<td style="padding: 10px 15px; font-weight: bold; border-bottom: 1px solid #ebeef2; color: #666; font-size: 13px;">Tahun & Kelas</td>' +
                '<td style="padding: 10px 15px; border-bottom: 1px solid #ebeef2; color: #222; font-size: 13px;">' + escapeHtml_(studentClass) + '</td>' +
              '</tr>' +
              '<tr>' +
                '<td style="padding: 10px 15px; font-weight: bold; border-bottom: 1px solid #ebeef2; color: #666; font-size: 13px;">ID DELIMa</td>' +
                '<td style="padding: 10px 15px; border-bottom: 1px solid #ebeef2; color: #222; font-size: 13px;">' + (studentEmail ? escapeHtml_(studentEmail) : '<span style="color:#999;">Tidak Dinyatakan</span>') + '</td>' +
              '</tr>' +
              '<tr>' +
                '<td style="padding: 10px 15px; font-weight: bold; color: #666; font-size: 13px;">Cadangan Password</td>' +
                '<td style="padding: 10px 15px; color: #d63384; font-weight: bold; font-size: 13px;">' + pwdDisplay + '</td>' +
              '</tr>' +
            '</table>' +
            '<div style="background-color: #fff9e6; border-left: 4px solid #ffc107; padding: 12px 15px; font-size: 12px; color: #856404; margin-bottom: 20px; border-radius: 4px;">' +
              '<strong>Peringatan Keselamatan:</strong> Sila pastikan identiti murid disahkan sebelum mengemas kini kata laluan dalam portal pengurusan DELIMa.' +
            '</div>' +
            '<div style="font-size: 11px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 15px;">' +
              'Tarikh Permohonan: ' + timestampStr + '<br>' +
              'Sistem ini dijana secara automatik oleh Google Apps Script SK Seksyen 24.' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    // 6. Hantar Emel
    var emailSent = false;
    var emailError = "";

    try {
      MailApp.sendEmail({
        to: adminEmail,
        subject: subject,
        body: plainBody,
        htmlBody: htmlBody,
        name: "Portal id-Delima SKS24"
      });
      emailSent = true;
    } catch (mailErr) {
      emailError = mailErr.toString();
      console.warn("Percubaan MailApp gagal (" + emailError + "). Mencuba GmailApp...");
      try {
        GmailApp.sendEmail(adminEmail, subject, plainBody, {
          htmlBody: htmlBody,
          name: "Portal id-Delima SKS24"
        });
        emailSent = true;
      } catch (gmailErr) {
        emailError += " | GmailApp: " + gmailErr.toString();
        console.error("Semua kaedah penghantaran emel gagal: " + emailError);
      }
    }

    // 7. Simpan Log Rekod ke Google Sheet dengan Perlindungan Formula Injection
    var logStatus = emailSent ? "Berjaya Dihantar" : "Gagal Emel (Disimpan Dalam Sheet: " + emailError + ")";
    logPasswordResetRequest_(studentName, studentClass, studentEmail, newPassword, logStatus);

    if (emailSent) {
      return { 
        success: true, 
        message: "Permohonan anda telah berjaya dihantar kepada admin sekolah!" 
      };
    } else {
      return { 
        success: true, 
        warning: true,
        message: "Permohonan anda telah berjaya direkodkan dalam sistem sekolah untuk tindakan admin." 
      };
    }

  } catch (error) {
    console.error("Ralat dalam sendPasswordResetEmail: " + error.toString());
    return { 
      success: false, 
      error: "Ralat sistem semasa memproses permohonan. Sila hubungi guru penyelaras DELIMa anda." 
    };
  }
}