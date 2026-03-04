require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const multer = require("multer");
const { google } = require("googleapis");
const { Readable } = require("stream");
const { randomInt } = require("crypto");
const PDFDocument = require("pdfkit");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || "0.0.0.0";
const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_USER = process.env.DB_USER || "root";
const DB_PASSWORD = process.env.DB_PASSWORD || "1234";
const DB_NAME = process.env.DB_NAME || "courier_app";
const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES || 10);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 30);
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);

const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = String(process.env.SMTP_PASS || "").replace(/\s+/g, "");
const OTP_FROM_EMAIL = process.env.OTP_FROM_EMAIL || SMTP_USER;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "admin@allworldexpress.com").trim().toLowerCase();
const ADMIN_NAME = String(process.env.ADMIN_NAME || "Admin").trim() || "Admin";
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "admin12345");
const ADMIN_PASSWORD_HASH = String(process.env.ADMIN_PASSWORD_HASH || "").trim();
const ADMIN_PANEL_KEY = String(process.env.ADMIN_PANEL_KEY || "").trim();
const GOOGLE_SERVICE_ACCOUNT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || "";
const GOOGLE_PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
const GOOGLE_DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID || "";
const GOOGLE_OAUTH_CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID || "";
const GOOGLE_OAUTH_CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET || "";
const GOOGLE_OAUTH_REFRESH_TOKEN = process.env.GOOGLE_OAUTH_REFRESH_TOKEN || "";
const EMPLOYEE_DRIVE_ROOT_FOLDER_ID =
  process.env.GOOGLE_EMPLOYEE_ROOT_FOLDER_ID || "1IHvr4oE6bfBx_vbNHHCpWmAqMKgsHSvZ";
const COMPANY_DRIVE_ROOT_FOLDER_ID =
  process.env.GOOGLE_COMPANY_ROOT_FOLDER_ID || "1LJ22A06Q9cklwjtfSrGzEcMr667XQOco";
const EMPLOYEE_IMAGE_MAX_BYTES = 100 * 1024;
const GSTIN_REGEX = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
const PAN_REGEX = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
const CIN_REGEX = /^[A-Z]{1}[0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$/;

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const otpStore = new Map();
const verifiedEmails = new Map();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
});

const transporter =
  SMTP_HOST && SMTP_USER && SMTP_PASS
    ? nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      })
    : null;

async function ensureEmployeeTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS employee (
      id INT AUTO_INCREMENT PRIMARY KEY,
      employee_id CHAR(10) UNIQUE,
      name VARCHAR(100) NOT NULL,
      number VARCHAR(15) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_blocked TINYINT(1) NOT NULL DEFAULT 0,
      blocked_at DATETIME NULL
    );
  `;

  await pool.query(sql);

  const [formDataColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND COLUMN_NAME = 'form_data'
     LIMIT 1`,
    [DB_NAME]
  );

  if (!formDataColumn.length) {
    await pool.query("ALTER TABLE employee_docs ADD COLUMN form_data LONGTEXT NULL AFTER pdf_link");
  }

  const [passwordColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee' AND COLUMN_NAME = 'password'
     LIMIT 1`,
    [DB_NAME]
  );

  if (!passwordColumn.length) {
    await pool.query("ALTER TABLE employee ADD COLUMN password VARCHAR(255) NULL AFTER email");
  }

  const [employeeIdColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee' AND COLUMN_NAME = 'employee_id'
     LIMIT 1`,
    [DB_NAME]
  );

  if (!employeeIdColumn.length) {
    await pool.query("ALTER TABLE employee ADD COLUMN employee_id CHAR(10) NULL AFTER id");
  }

  const [employeeIdIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee' AND INDEX_NAME = 'uniq_employee_employee_id'
     LIMIT 1`,
    [DB_NAME]
  );

  if (!employeeIdIndex.length) {
    await pool.query("CREATE UNIQUE INDEX uniq_employee_employee_id ON employee (employee_id)");
  }

  const employeeProfileColumns = [
    {
      columnName: "address",
      ddl: "ALTER TABLE employee ADD COLUMN address TEXT NULL AFTER login_time",
    },
    {
      columnName: "dob",
      ddl: "ALTER TABLE employee ADD COLUMN dob DATE NULL AFTER address",
    },
    {
      columnName: "pan_card_link",
      ddl: "ALTER TABLE employee ADD COLUMN pan_card_link TEXT NULL AFTER dob",
    },
    {
      columnName: "bank_account_number",
      ddl: "ALTER TABLE employee ADD COLUMN bank_account_number VARCHAR(40) NULL AFTER pan_card_link",
    },
    {
      columnName: "bank_passbook_link",
      ddl: "ALTER TABLE employee ADD COLUMN bank_passbook_link TEXT NULL AFTER bank_account_number",
    },
    {
      columnName: "aadhaar_link",
      ddl: "ALTER TABLE employee ADD COLUMN aadhaar_link TEXT NULL AFTER bank_passbook_link",
    },
    {
      columnName: "photo_link",
      ddl: "ALTER TABLE employee ADD COLUMN photo_link TEXT NULL AFTER aadhaar_link",
    },
    {
      columnName: "date_of_joining",
      ddl: "ALTER TABLE employee ADD COLUMN date_of_joining DATE NULL AFTER photo_link",
    },
    {
      columnName: "role",
      ddl: "ALTER TABLE employee ADD COLUMN role VARCHAR(120) NULL AFTER date_of_joining",
    },
    {
      columnName: "terms_points",
      ddl: "ALTER TABLE employee ADD COLUMN terms_points LONGTEXT NULL AFTER role",
    },
    {
      columnName: "profile_pdf_link",
      ddl: "ALTER TABLE employee ADD COLUMN profile_pdf_link TEXT NULL AFTER terms_points",
    },
    {
      columnName: "profile_folder_id",
      ddl: "ALTER TABLE employee ADD COLUMN profile_folder_id VARCHAR(255) NULL AFTER profile_pdf_link",
    },
    {
      columnName: "is_blocked",
      ddl: "ALTER TABLE employee ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0 AFTER profile_folder_id",
    },
    {
      columnName: "blocked_at",
      ddl: "ALTER TABLE employee ADD COLUMN blocked_at DATETIME NULL AFTER is_blocked",
    },
  ];

  for (const col of employeeProfileColumns) {
    const [exists] = await pool.query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee' AND COLUMN_NAME = ?
       LIMIT 1`,
      [DB_NAME, col.columnName]
    );
    if (!exists.length) {
      await pool.query(col.ddl);
    }
  }

  const [rowsWithoutEmployeeId] = await pool.query(
    "SELECT id FROM employee WHERE employee_id IS NULL OR employee_id = ''"
  );

  for (const row of rowsWithoutEmployeeId) {
    const generatedEmployeeId = await generateUniqueEmployeeId();
    await pool.query("UPDATE employee SET employee_id = ? WHERE id = ?", [
      generatedEmployeeId,
      row.id,
    ]);
  }
}

async function ensureEmployeeDocsTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS employee_docs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      employee_id INT NOT NULL,
      awb_no VARCHAR(120) NOT NULL,
      form_type ENUM('Doct','Manifest') NOT NULL DEFAULT 'Doct',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      pdf_link TEXT NULL,
      form_data LONGTEXT NULL,
      KEY idx_employee_docs_employee_id (employee_id),
      CONSTRAINT fk_employee_docs_employee
        FOREIGN KEY (employee_id) REFERENCES employee(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
    ) ENGINE=InnoDB;
  `;

  await pool.query(sql);

  // Backward compatibility if older table name exists.
  const [legacyTable] = await pool.query(
    `SELECT TABLE_NAME
     FROM INFORMATION_SCHEMA.TABLES
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_doct'
     LIMIT 1`,
    [DB_NAME]
  );

  if (legacyTable.length) {
    await pool.query(
      `INSERT INTO employee_docs (employee_id, awb_no, form_type, created_at, pdf_link)
       SELECT d.employee_id, d.awb_no, d.form_type, d.created_at, d.pdf_link
       FROM employee_doct d
       LEFT JOIN employee_docs n
         ON n.employee_id = d.employee_id
        AND n.awb_no = d.awb_no
        AND n.form_type = d.form_type
        AND n.created_at = d.created_at
       WHERE n.id IS NULL`
    );
  }
}

async function ensureAirwayBillsTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS airwaybills (
      id INT AUTO_INCREMENT PRIMARY KEY,
      awb_number VARCHAR(120) NOT NULL,
      consignor_name VARCHAR(200) NULL,
      pdf_link TEXT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_airwaybills_awb_number (awb_number)
    ) ENGINE=InnoDB;
  `;

  await pool.query(sql);

  const [consignorNameColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'airwaybills' AND COLUMN_NAME = 'consignor_name'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!consignorNameColumn.length) {
    await pool.query("ALTER TABLE airwaybills ADD COLUMN consignor_name VARCHAR(200) NULL AFTER awb_number");
  }

  const [pdfLinkColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'airwaybills' AND COLUMN_NAME = 'pdf_link'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!pdfLinkColumn.length) {
    await pool.query("ALTER TABLE airwaybills ADD COLUMN pdf_link TEXT NULL AFTER consignor_name");
  }

  const [createdAtColumn] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'airwaybills' AND COLUMN_NAME = 'created_at'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!createdAtColumn.length) {
    await pool.query(
      "ALTER TABLE airwaybills ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER pdf_link"
    );
  }

  const [awbIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'airwaybills' AND INDEX_NAME = 'uniq_airwaybills_awb_number'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!awbIndex.length) {
    await pool.query("ALTER TABLE airwaybills ADD UNIQUE INDEX uniq_airwaybills_awb_number (awb_number)");
  }
}

async function ensureCompanyTable() {
  const sql = `
    CREATE TABLE IF NOT EXISTS company (
      id INT AUTO_INCREMENT PRIMARY KEY,
      company_unique_id CHAR(10) NOT NULL UNIQUE,
      company_name VARCHAR(200) NOT NULL,
      trade_name VARCHAR(200) NULL,
      business_type VARCHAR(120) NOT NULL,
      gst_number VARCHAR(50) NOT NULL,
      pan_number VARCHAR(50) NOT NULL,
      pan_card_link TEXT NULL,
      cin_number VARCHAR(60) NOT NULL,
      registered_address TEXT NOT NULL,
      operational_address TEXT NOT NULL,
      contact_full_name VARCHAR(150) NOT NULL,
      mobile_number VARCHAR(20) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      password VARCHAR(255) NULL,
      profile_pdf_link TEXT NULL,
      profile_folder_id VARCHAR(255) NULL,
      is_blocked TINYINT(1) NOT NULL DEFAULT 0,
      blocked_at DATETIME NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
  `;

  await pool.query(sql);

  const columns = [
    ["company_unique_id", "ALTER TABLE company ADD COLUMN company_unique_id CHAR(10) NULL AFTER id"],
    ["company_name", "ALTER TABLE company ADD COLUMN company_name VARCHAR(200) NULL AFTER company_unique_id"],
    ["trade_name", "ALTER TABLE company ADD COLUMN trade_name VARCHAR(200) NULL AFTER company_name"],
    ["business_type", "ALTER TABLE company ADD COLUMN business_type VARCHAR(120) NULL AFTER trade_name"],
    ["gst_number", "ALTER TABLE company ADD COLUMN gst_number VARCHAR(50) NULL AFTER business_type"],
    ["pan_number", "ALTER TABLE company ADD COLUMN pan_number VARCHAR(50) NULL AFTER gst_number"],
    ["pan_card_link", "ALTER TABLE company ADD COLUMN pan_card_link TEXT NULL AFTER pan_number"],
    ["cin_number", "ALTER TABLE company ADD COLUMN cin_number VARCHAR(60) NULL AFTER pan_card_link"],
    ["registered_address", "ALTER TABLE company ADD COLUMN registered_address TEXT NULL AFTER cin_number"],
    ["operational_address", "ALTER TABLE company ADD COLUMN operational_address TEXT NULL AFTER registered_address"],
    ["contact_full_name", "ALTER TABLE company ADD COLUMN contact_full_name VARCHAR(150) NULL AFTER operational_address"],
    ["mobile_number", "ALTER TABLE company ADD COLUMN mobile_number VARCHAR(20) NULL AFTER contact_full_name"],
    ["email", "ALTER TABLE company ADD COLUMN email VARCHAR(150) NULL AFTER mobile_number"],
    ["password", "ALTER TABLE company ADD COLUMN password VARCHAR(255) NULL AFTER email"],
    ["profile_pdf_link", "ALTER TABLE company ADD COLUMN profile_pdf_link TEXT NULL AFTER password"],
    ["profile_folder_id", "ALTER TABLE company ADD COLUMN profile_folder_id VARCHAR(255) NULL AFTER profile_pdf_link"],
    ["is_blocked", "ALTER TABLE company ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0 AFTER profile_folder_id"],
    ["blocked_at", "ALTER TABLE company ADD COLUMN blocked_at DATETIME NULL AFTER is_blocked"],
    ["created_at", "ALTER TABLE company ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER blocked_at"],
  ];

  for (const [columnName, ddl] of columns) {
    const [exists] = await pool.query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'company' AND COLUMN_NAME = ?
       LIMIT 1`,
      [DB_NAME, columnName]
    );
    if (!exists.length) {
      await pool.query(ddl);
    }
  }

  const [uniqIdIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'company' AND INDEX_NAME = 'uniq_company_unique_id'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!uniqIdIndex.length) {
    await pool.query("CREATE UNIQUE INDEX uniq_company_unique_id ON company (company_unique_id)");
  }

  const [emailIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'company' AND INDEX_NAME = 'uniq_company_email'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!emailIndex.length) {
    await pool.query("CREATE UNIQUE INDEX uniq_company_email ON company (email)");
  }
}

function getConsignorCode(consignorName) {
  const lettersOnly = String(consignorName || "")
    .toUpperCase()
    .replace(/[^A-Z]/g, "");
  const firstFour = lettersOnly.slice(0, 4);
  return firstFour.padEnd(4, "X");
}

function formatAwbNo(consignorCode, sequenceNo) {
  const nextSerial = String(sequenceNo).padStart(4, "0");
  return `AWE-${consignorCode}-${nextSerial}`;
}

async function allocateNextAwb({ formType, consignor, employeeDbId }) {
  const safeFormType = formType === "Manifest" ? "Manifest" : "Doct";
  const cleanConsignor = String(consignor || "").trim();
  if (!cleanConsignor) {
    throw new Error("consignor is required");
  }

  const consignorCode = getConsignorCode(cleanConsignor);
  const [rows] = await pool.query(
    `SELECT awb_number
     FROM airwaybills
     WHERE awb_number LIKE ?
     ORDER BY awb_number DESC
     LIMIT 1`,
    [`AWE-${consignorCode}-%`]
  );

  const lastAwb = rows.length ? String(rows[0].awb_number || "") : "";
  const suffixMatch = lastAwb.match(/-(\d+)$/);
  const lastSequence = suffixMatch ? Number(suffixMatch[1]) : 0;
  const nextSequence = lastSequence + 1;
  const awbNo = formatAwbNo(consignorCode, nextSequence);

  return {
    id: null,
    awbNo,
    sequenceNo: nextSequence,
    consignorCode,
    formType: safeFormType,
    employeeDbId: employeeDbId || null,
  };
}

function createTenDigitId() {
  const firstDigit = randomInt(1, 10);
  let out = String(firstDigit);
  for (let i = 0; i < 9; i += 1) {
    out += String(randomInt(0, 10));
  }
  return out;
}

async function generateUniqueEmployeeId() {
  for (let attempt = 0; attempt < 25; attempt += 1) {
    const candidateId = createTenDigitId();
    const [existing] = await pool.query(
      "SELECT id FROM employee WHERE employee_id = ? LIMIT 1",
      [candidateId]
    );
    if (!existing.length) {
      return candidateId;
    }
  }

  throw new Error("Could not generate unique 10-digit employee ID");
}

async function generateUniqueCompanyId() {
  for (let attempt = 0; attempt < 25; attempt += 1) {
    const candidateId = createTenDigitId();
    const [existing] = await pool.query(
      "SELECT id FROM company WHERE company_unique_id = ? LIMIT 1",
      [candidateId]
    );
    if (!existing.length) {
      return candidateId;
    }
  }

  throw new Error("Could not generate unique 10-digit company ID");
}

function isDriveConfigured() {
  const hasServiceAccountAuth = Boolean(GOOGLE_SERVICE_ACCOUNT_EMAIL) && Boolean(GOOGLE_PRIVATE_KEY);
  const hasOAuthAuth =
    Boolean(GOOGLE_OAUTH_CLIENT_ID) &&
    Boolean(GOOGLE_OAUTH_CLIENT_SECRET) &&
    Boolean(GOOGLE_OAUTH_REFRESH_TOKEN);
  const hasFolderTarget =
    Boolean(GOOGLE_DRIVE_FOLDER_ID) ||
    Boolean(EMPLOYEE_DRIVE_ROOT_FOLDER_ID) ||
    Boolean(COMPANY_DRIVE_ROOT_FOLDER_ID);

  return (hasServiceAccountAuth || hasOAuthAuth) && hasFolderTarget;
}

function getDriveClient() {
  const hasOAuthAuth =
    Boolean(GOOGLE_OAUTH_CLIENT_ID) &&
    Boolean(GOOGLE_OAUTH_CLIENT_SECRET) &&
    Boolean(GOOGLE_OAUTH_REFRESH_TOKEN);

  if (hasOAuthAuth) {
    const auth = new google.auth.OAuth2({
      clientId: GOOGLE_OAUTH_CLIENT_ID,
      clientSecret: GOOGLE_OAUTH_CLIENT_SECRET,
    });
    auth.setCredentials({ refresh_token: GOOGLE_OAUTH_REFRESH_TOKEN });
    return google.drive({ version: "v3", auth });
  }

  const auth = new google.auth.JWT({
    email: GOOGLE_SERVICE_ACCOUNT_EMAIL,
    key: GOOGLE_PRIVATE_KEY,
    scopes: ["https://www.googleapis.com/auth/drive"],
  });
  return google.drive({ version: "v3", auth });
}

function extractDriveFileId(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";
  const idLike = raw.match(/^[a-zA-Z0-9_-]{10,}$/);
  if (idLike) return idLike[0];
  const byPath = raw.match(/\/d\/([a-zA-Z0-9_-]+)/);
  if (byPath?.[1]) return byPath[1];
  const byQuery = raw.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  if (byQuery?.[1]) return byQuery[1];
  return "";
}

function escapeDriveQueryValue(input) {
  return String(input || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

async function uploadPdfToDrive({ fileBuffer, fileName, existingFileId = "" }) {
  const drive = getDriveClient();
  let fileId = String(existingFileId || "").trim();

  const escapedName = escapeDriveQueryValue(fileName);
  const escapedFolderId = escapeDriveQueryValue(GOOGLE_DRIVE_FOLDER_ID);
  const listQuery = `'${escapedFolderId}' in parents and trashed=false and mimeType='application/pdf' and name='${escapedName}'`;

  if (fileId) {
    await drive.files.update({
      fileId,
      supportsAllDrives: true,
      requestBody: {
        name: fileName,
        mimeType: "application/pdf",
      },
      media: {
        mimeType: "application/pdf",
        body: Readable.from(fileBuffer),
      },
      fields: "id,name",
    });
  } else {
    const existingByName = await drive.files.list({
      q: listQuery,
      fields: "files(id,name,modifiedTime)",
      pageSize: 50,
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
    });

    const byNameFiles = Array.isArray(existingByName.data?.files)
      ? [...existingByName.data.files].sort(
          (a, b) => new Date(b.modifiedTime || 0).getTime() - new Date(a.modifiedTime || 0).getTime()
        )
      : [];

    if (byNameFiles.length) {
      fileId = byNameFiles[0].id;
      await drive.files.update({
        fileId,
        supportsAllDrives: true,
        requestBody: {
          name: fileName,
          mimeType: "application/pdf",
        },
        media: {
          mimeType: "application/pdf",
          body: Readable.from(fileBuffer),
        },
        fields: "id,name",
      });
    } else {
      const createRes = await drive.files.create({
        requestBody: {
          name: fileName,
          parents: [GOOGLE_DRIVE_FOLDER_ID],
          mimeType: "application/pdf",
        },
        media: {
          mimeType: "application/pdf",
          body: Readable.from(fileBuffer),
        },
        fields: "id,name",
        supportsAllDrives: true,
      });
      fileId = createRes.data.id;
      await drive.permissions.create({
        fileId,
        supportsAllDrives: true,
        requestBody: {
          role: "reader",
          type: "anyone",
        },
      });
    }
  }

  // Keep only one PDF per filename inside target folder to avoid duplicates.
  const postList = await drive.files.list({
    q: listQuery,
    fields: "files(id,name,modifiedTime)",
    pageSize: 100,
    supportsAllDrives: true,
    includeItemsFromAllDrives: true,
  });
  const sameNameFiles = Array.isArray(postList.data?.files) ? postList.data.files : [];
  const duplicatesToDelete = sameNameFiles
    .filter((f) => f?.id && f.id !== fileId)
    .map((f) => f.id);

  for (const duplicateId of duplicatesToDelete) {
    await drive.files.delete({
      fileId: duplicateId,
      supportsAllDrives: true,
    });
  }


  return {
    fileId,
    viewLink: `https://drive.google.com/file/d/${fileId}/view`,
  };
}

function sanitizeDriveName(input) {
  return String(input || "")
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

async function ensureDriveFolder({ parentId, folderName }) {
  const drive = getDriveClient();
  const safeName = sanitizeDriveName(folderName) || `Employee-${Date.now()}`;
  const escapedParent = escapeDriveQueryValue(parentId);
  const escapedName = escapeDriveQueryValue(safeName);
  const q = `'${escapedParent}' in parents and trashed=false and mimeType='application/vnd.google-apps.folder' and name='${escapedName}'`;

  const existing = await drive.files.list({
    q,
    fields: "files(id,name,createdTime)",
    pageSize: 20,
    supportsAllDrives: true,
    includeItemsFromAllDrives: true,
  });
  const folders = Array.isArray(existing.data?.files) ? existing.data.files : [];
  if (folders.length) {
    return { folderId: folders[0].id, folderName: safeName };
  }

  const created = await drive.files.create({
    requestBody: {
      name: safeName,
      mimeType: "application/vnd.google-apps.folder",
      parents: [parentId],
    },
    fields: "id,name",
    supportsAllDrives: true,
  });

  return { folderId: created.data.id, folderName: safeName };
}

async function uploadBinaryToDrive({
  parentId,
  fileBuffer,
  fileName,
  mimeType,
  existingFileId = "",
}) {
  const drive = getDriveClient();
  let fileId = String(existingFileId || "").trim();

  if (fileId) {
    await drive.files.update({
      fileId,
      supportsAllDrives: true,
      requestBody: {
        name: fileName,
        mimeType,
      },
      media: {
        mimeType,
        body: Readable.from(fileBuffer),
      },
      fields: "id,name",
    });
  } else {
    const created = await drive.files.create({
      requestBody: {
        name: fileName,
        mimeType,
        parents: [parentId],
      },
      media: {
        mimeType,
        body: Readable.from(fileBuffer),
      },
      fields: "id,name",
      supportsAllDrives: true,
    });
    fileId = created.data.id;
  }

  await drive.permissions.create({
    fileId,
    supportsAllDrives: true,
    requestBody: {
      role: "reader",
      type: "anyone",
    },
  });

  return {
    fileId,
    viewLink: `https://drive.google.com/file/d/${fileId}/view`,
  };
}

function normalizeTermsPoints(input) {
  const lines = String(input || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length) return lines;

  return [
    "Employee will follow company operational and security policies.",
    "Documents shared during onboarding must be valid and authentic.",
    "Confidential information must not be disclosed without authorization.",
    "Attendance and reporting timelines must be followed.",
  ];
}

function formatDateForPdf(input) {
  const raw = String(input || "").trim();
  if (!raw) return "-";
  const asDate = new Date(raw);
  if (Number.isNaN(asDate.getTime())) return raw;
  const dd = String(asDate.getDate()).padStart(2, "0");
  const mm = String(asDate.getMonth() + 1).padStart(2, "0");
  const yyyy = asDate.getFullYear();
  return `${dd}-${mm}-${yyyy}`;
}

function drawLabelValueRow(doc, label, value) {
  doc.font("Helvetica-Bold").fontSize(10).text(`${label}:`, { continued: true });
  doc.font("Helvetica").fontSize(10).text(` ${value || "-"}`);
}

function tryDrawImageBox(doc, imageBuffer, box, fallbackText) {
  const { x, y, width, height } = box;
  doc.save();
  doc.rect(x, y, width, height).stroke("#CBD5E1");
  try {
    doc.image(imageBuffer, x + 6, y + 6, {
      fit: [width - 12, height - 30],
      align: "center",
      valign: "center",
    });
  } catch {
    doc
      .font("Helvetica")
      .fontSize(9)
      .fillColor("#475569")
      .text(fallbackText || "Image preview unavailable", x + 8, y + height / 2 - 8, {
        width: width - 16,
        align: "center",
      });
  }
  doc.restore();
}

function buildEmployeeProfilePdfBuffer({ employeeId, form, termsPoints, imageLinks, imageBuffers }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: "A4" });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const pageWidth = doc.page.width;
    const usableWidth = pageWidth - 96;
    doc.rect(36, 36, pageWidth - 72, doc.page.height - 72).lineWidth(1).stroke("#94A3B8");

    doc.fillColor("#0F172A").font("Helvetica-Bold").fontSize(20).text("ALL WORLD EXPRESS", {
      align: "center",
    });
    doc.moveDown(0.2);
    doc.fillColor("#1E293B").font("Helvetica-Bold").fontSize(14).text("Hired Employee of All World Express", {
      align: "center",
    });
    doc.moveDown(0.6);

    doc
      .lineWidth(0.8)
      .moveTo(54, doc.y)
      .lineTo(pageWidth - 54, doc.y)
      .stroke("#CBD5E1");
    doc.moveDown(0.8);

    drawLabelValueRow(doc, "Employee ID", employeeId);
    drawLabelValueRow(doc, "Full Name", form.fullName);
    drawLabelValueRow(doc, "Mobile", form.number);
    drawLabelValueRow(doc, "Email", form.email);
    drawLabelValueRow(doc, "Address", form.address || "-");
    drawLabelValueRow(doc, "Date of Birth", formatDateForPdf(form.dob));
    drawLabelValueRow(doc, "Date of Joining", formatDateForPdf(form.dateOfJoining));
    drawLabelValueRow(doc, "Bank Account Number", form.bankAccountNumber || "-");
    drawLabelValueRow(doc, "Designation/Role", form.role || "-");
    drawLabelValueRow(doc, "Issue Date", formatDateForPdf(new Date().toISOString().slice(0, 10)));
    doc.moveDown(0.9);

    doc.font("Helvetica-Bold").fontSize(12).fillColor("#0F172A").text("Employee Documents", {
      width: usableWidth,
    });
    doc.moveDown(0.3);

    const gridTop = doc.y;
    const gap = 14;
    const boxWidth = (usableWidth - gap) / 2;
    const boxHeight = 125;
    const x1 = 48;
    const x2 = x1 + boxWidth + gap;
    const y1 = gridTop;
    const y2 = gridTop + boxHeight + 26;

    tryDrawImageBox(doc, imageBuffers.photoImage, { x: x1, y: y1, width: boxWidth, height: boxHeight }, "Photo");
    tryDrawImageBox(doc, imageBuffers.aadhaarImage, { x: x2, y: y1, width: boxWidth, height: boxHeight }, "Aadhaar");
    tryDrawImageBox(
      doc,
      imageBuffers.panCardImage,
      { x: x1, y: y2, width: boxWidth, height: boxHeight },
      "PAN Card"
    );
    tryDrawImageBox(
      doc,
      imageBuffers.bankPassbookImage,
      { x: x2, y: y2, width: boxWidth, height: boxHeight },
      "Bank Passbook"
    );

    doc.font("Helvetica-Bold").fontSize(9).fillColor("#1E293B").text("Photo", x1, y1 + boxHeight + 8, {
      width: boxWidth,
      align: "center",
    });
    doc.font("Helvetica-Bold").fontSize(9).text("Aadhaar", x2, y1 + boxHeight + 8, {
      width: boxWidth,
      align: "center",
    });
    doc.font("Helvetica-Bold").fontSize(9).text("PAN Card", x1, y2 + boxHeight + 8, {
      width: boxWidth,
      align: "center",
    });
    doc.font("Helvetica-Bold").fontSize(9).text("Bank Passbook", x2, y2 + boxHeight + 8, {
      width: boxWidth,
      align: "center",
    });

    doc.y = y2 + boxHeight + 34;
    doc.font("Helvetica").fontSize(9).fillColor("#475569").text(
      "This document is system-generated for onboarding and record verification purpose.",
      { align: "left" }
    );

    doc.addPage();
    doc.fillColor("#0F172A").font("Helvetica-Bold").fontSize(16).text("Labor Terms & Conditions", {
      align: "center",
    });
    doc.moveDown(0.5);
    doc.font("Helvetica").fontSize(11).fillColor("#111827");
    termsPoints.forEach((line, idx) => {
      doc.text(`${idx + 1}. ${line}`, { paragraphGap: 7, align: "justify" });
    });

    doc.moveDown(1.2);
    const signatureY = Math.max(doc.y + 30, doc.page.height - 170);
    const leftX = 70;
    const rightX = doc.page.width / 2 + 10;
    const signLineWidth = 200;

    doc
      .lineWidth(1)
      .moveTo(leftX, signatureY)
      .lineTo(leftX + signLineWidth, signatureY)
      .stroke("#334155");
    doc
      .moveTo(rightX, signatureY)
      .lineTo(rightX + signLineWidth, signatureY)
      .stroke("#334155");

    doc.font("Helvetica-Bold").fontSize(10).fillColor("#0F172A").text("Employee Signature", leftX, signatureY + 8, {
      width: signLineWidth,
      align: "center",
    });
    doc.font("Helvetica").fontSize(9).fillColor("#334155").text(form.fullName || "-", leftX, signatureY + 24, {
      width: signLineWidth,
      align: "center",
    });

    doc.font("Helvetica-Bold").fontSize(10).fillColor("#0F172A").text("Authorized Signature", rightX, signatureY + 8, {
      width: signLineWidth,
      align: "center",
    });
    doc.font("Helvetica").fontSize(9).fillColor("#334155").text("All World Express", rightX, signatureY + 24, {
      width: signLineWidth,
      align: "center",
    });

    doc.end();
  });
}

function buildCompanyProfilePdfBuffer({ companyId, form, panCardImageBuffer }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: "A4" });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const pageWidth = doc.page.width; // 595.28
    const pageHeight = doc.page.height; // 841.89
    const issueDate = formatDateForPdf(new Date().toISOString().slice(0, 10));
    const documentId = `AWE-${String(companyId || "").slice(0, 4)}-${String(issueDate).replace(/-/g, "")}`;

    const drawField = (label, value, x, y, width) => {
      doc.font("Helvetica").fontSize(9).fillColor("#55607A").text(label, x, y, { width });
      doc.font("Helvetica-Bold").fontSize(11).fillColor("#111B33").text(String(value || "-"), x, y + 13, {
        width,
      });
      return y + 46;
    };

    // Background and frame
    doc.rect(0, 0, pageWidth, pageHeight).fill("#F3F5FA");
    doc.roundedRect(20, 20, pageWidth - 40, pageHeight - 40, 16).lineWidth(1).stroke("#CED5E3");

    // Header strip
    doc.rect(20, 20, pageWidth - 40, 72).fill("#1F2E56");
    doc.font("Helvetica-Bold").fontSize(25).fillColor("#FFFFFF").text("ALL WORLD EXPRESS", 20, 44, {
      width: pageWidth - 40,
      align: "center",
    });
    doc.rect(20, 91, pageWidth - 40, 2).fill("#304778");

    // Meta section
    doc.font("Helvetica").fontSize(9).fillColor("#27324D").text(`Document ID: ${documentId}`, pageWidth - 220, 124, {
      width: 180,
      align: "left",
    });
    doc.text(`Generated On: ${issueDate}`, pageWidth - 220, 142, { width: 180, align: "left" });
    doc.moveTo(48, 168).lineTo(pageWidth - 48, 168).stroke("#D6DCE8");

    // Title
    doc.font("Helvetica").fontSize(24).fillColor("#111B33").text("Company Onboarding Certificate", 20, 198, {
      width: pageWidth - 40,
      align: "center",
    });

    // Main details card
    const cardX = 36;
    const cardY = 248;
    const cardW = pageWidth - 72;
    const cardH = 530;
    doc.roundedRect(cardX, cardY, cardW, cardH, 14).fillAndStroke("#FFFFFF", "#D7DDEA");

    // Faint watermark style circle
    doc.save();
    doc.fillOpacity(0.04);
    doc.circle(pageWidth / 2, 545, 110).fill("#8A94AB");
    doc.fillOpacity(1);
    doc.restore();

    const colGap = 22;
    const colW = (cardW - colGap - 48) / 2;
    const leftColX = cardX + 24;
    const rightColX = leftColX + colW + colGap;
    doc.moveTo(rightColX - 11, cardY + 26).lineTo(rightColX - 11, cardY + 330).stroke("#E0E5EF");

    let ly = cardY + 20;
    ly = drawField("Company ID", companyId, leftColX, ly, colW);
    ly = drawField("Company Name", form.companyName, leftColX, ly, colW);
    ly = drawField("Trade Name", form.tradeName || "-", leftColX, ly, colW);
    ly = drawField("Business Type", form.businessType, leftColX, ly, colW);
    ly = drawField("GST Number", form.gstNumber, leftColX, ly, colW);
    ly = drawField("PAN Number", form.panNumber, leftColX, ly, colW);
    drawField("CIN Number", form.cinNumber, leftColX, ly, colW);

    let ry = cardY + 20;
    ry = drawField("Registered Address", form.registeredAddress, rightColX, ry, colW);
    ry = drawField("Operational Address", form.operationalAddress, rightColX, ry, colW);
    ry = drawField("Contact Name", form.contactFullName, rightColX, ry, colW);
    ry = drawField("Mobile Number", form.mobileNumber, rightColX, ry, colW);
    ry = drawField("Email", form.email, rightColX, ry, colW);
    doc.moveTo(rightColX, ry - 3).lineTo(rightColX + colW, ry - 3).stroke("#E0E5EF");
    drawField("Issue Date", issueDate, rightColX, ry + 6, colW);

    // PAN section divider
    doc.moveTo(cardX + 24, cardY + 335).lineTo(cardX + cardW - 24, cardY + 335).stroke("#E0E5EF");
    doc.font("Helvetica-Bold").fontSize(13).fillColor("#16213D").text("PAN Card Verification Document", cardX + 24, cardY + 355, {
      width: cardW - 48,
    });

    // PAN and signature card
    const panBoxX = cardX + 20;
    const panBoxY = cardY + 390;
    const panBoxW = cardW - 40;
    const panBoxH = 152;
    doc.roundedRect(panBoxX, panBoxY, panBoxW, panBoxH, 12).fillAndStroke("#FDFEFF", "#D7DDEA");

    tryDrawImageBox(
      doc,
      panCardImageBuffer,
      { x: panBoxX + 18, y: panBoxY + 18, width: 190, height: 108 },
      "PAN card image"
    );

    const sigX = panBoxX + panBoxW - 170;
    const sigY = panBoxY + 90;
    doc.font("Helvetica").fontSize(11).fillColor("#16213D").text("Authorized Signatory", sigX - 5, panBoxY + 82, {
      width: 155,
      align: "center",
    });
    doc.moveTo(sigX, sigY + 20).lineTo(sigX + 130, sigY + 20).stroke("#8B95AA");
    doc.font("Helvetica").fontSize(8).fillColor("#2A3552").text("All World Express", sigX, sigY + 28, {
      width: 130,
      align: "center",
    });

    doc.font("Helvetica").fontSize(8).fillColor("#5B667F").text(
      "This certificate is digitally generated for onboarding and compliance verification purposes.",
      panBoxX + 18,
      panBoxY + 128,
      { width: panBoxW - 36, align: "left" }
    );

    // Bottom footer
    doc.moveTo(56, pageHeight - 84).lineTo(pageWidth - 56, pageHeight - 84).stroke("#D6DCE8");
    doc.font("Helvetica").fontSize(10).fillColor("#55607A").text("Confidential - For Official Use Only", 20, pageHeight - 68, {
      width: pageWidth - 40,
      align: "center",
    });

    doc.end();
  });
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, message: "Server and DB are running" });
  } catch (_err) {
    res.status(500).json({ ok: false, message: "DB connection failed" });
  }
});

app.post("/api/drive/upload", upload.single("file"), async (req, res) => {
  try {
    if (!isDriveConfigured()) {
      return res.status(500).json({
        ok: false,
        message:
          "Google Drive is not configured. Use either service account (GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_PRIVATE_KEY) or OAuth (GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, GOOGLE_OAUTH_REFRESH_TOKEN), plus GOOGLE_DRIVE_FOLDER_ID.",
      });
    }

    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ ok: false, message: "PDF file is required" });
    }

    const fileName = String(req.body?.fileName || req.file.originalname || "doct.pdf").trim();
    let existingFileId =
      extractDriveFileId(req.body?.existingFileId) || extractDriveFileId(req.body?.existingLink);

    // Extra safety for edit flow: if client did not send existing link/id, fetch it from DB.
    if (!existingFileId) {
      const docId = Number(req.body?.docId || 0);
      const employeeDbId = await resolveEmployeeDbId(req.body?.employeeId);
      if (docId > 0 && employeeDbId) {
        const [docRows] = await pool.query(
          `SELECT pdf_link
           FROM employee_docs
           WHERE id = ? AND employee_id = ?
           LIMIT 1`,
          [docId, employeeDbId]
        );
        if (docRows.length && docRows[0]?.pdf_link) {
          existingFileId = extractDriveFileId(docRows[0].pdf_link);
        }
      }
    }

    const uploaded = await uploadPdfToDrive({
      fileBuffer: req.file.buffer,
      fileName,
      existingFileId,
    });

    return res.json({
      ok: true,
      message: "PDF uploaded to Google Drive",
      fileId: uploaded.fileId,
      link: uploaded.viewLink,
    });
  } catch (err) {
    console.error("Drive upload error:", err);
    const status = Number(err?.code || err?.status || 500);
    const providerMessage =
      err?.response?.data?.error?.message ||
      err?.cause?.message ||
      err?.message ||
      "Failed to upload PDF to Google Drive";

    if (status === 401) {
      if (/invalid_grant/i.test(providerMessage)) {
        return res.status(500).json({
          ok: false,
          message:
            "Google OAuth refresh token is invalid/expired. Re-generate GOOGLE_OAUTH_REFRESH_TOKEN.",
        });
      }
      return res.status(500).json({
        ok: false,
        message:
          "Google auth failed (401). Check OAuth credentials or service account key.",
      });
    }

    if (status === 403) {
      if (/Service Accounts do not have storage quota/i.test(providerMessage)) {
        return res.status(500).json({
          ok: false,
          message:
            "Service account has no personal Drive quota. Use a Shared Drive folder or switch to OAuth user upload.",
        });
      }
      return res.status(500).json({
        ok: false,
        message: `Google Drive access denied (403): ${providerMessage}`,
      });
    }

    if (status === 404 && /File not found/i.test(providerMessage)) {
      return res.status(500).json({
        ok: false,
        message:
          "GOOGLE_DRIVE_FOLDER_ID not found or not accessible. Check folder id and share folder with service account.",
      });
    }

    return res.status(500).json({ ok: false, message: providerMessage });
  }
});

async function resolveEmployeeDbId(input) {
  if (input === undefined || input === null) return null;
  const raw = String(input).trim();
  if (!raw) return null;

  if (/^\d+$/.test(raw)) {
    const [rowsByDbId] = await pool.query(
      "SELECT id FROM employee WHERE id = ? LIMIT 1",
      [Number(raw)]
    );
    if (rowsByDbId.length) return rowsByDbId[0].id;
  }

  const [rowsByEmpId] = await pool.query(
    "SELECT id FROM employee WHERE employee_id = ? LIMIT 1",
    [raw]
  );
  if (rowsByEmpId.length) return rowsByEmpId[0].id;

  return null;
}

async function resolveCompanyDbId(input) {
  if (input === undefined || input === null) return null;
  const raw = String(input).trim();
  if (!raw) return null;

  if (/^\d+$/.test(raw)) {
    const [rowsByDbId] = await pool.query(
      "SELECT id FROM company WHERE id = ? LIMIT 1",
      [Number(raw)]
    );
    if (rowsByDbId.length) return rowsByDbId[0].id;
  }

  const [rowsByCompanyId] = await pool.query(
    "SELECT id FROM company WHERE company_unique_id = ? LIMIT 1",
    [raw]
  );
  if (rowsByCompanyId.length) return rowsByCompanyId[0].id;

  return null;
}

function parseOptionalBoolean(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === "boolean") return value;

  const raw = String(value).trim().toLowerCase();
  if (!raw) return null;
  if (raw === "1" || raw === "true" || raw === "yes") return true;
  if (raw === "0" || raw === "false" || raw === "no") return false;
  return null;
}

function isAdminAuthorized(req) {
  if (!ADMIN_PANEL_KEY) return true;
  const key = String(req.headers["x-admin-key"] || "").trim();
  return key === ADMIN_PANEL_KEY;
}

async function isAdminPasswordValid(plainPassword) {
  const cleanPassword = String(plainPassword || "");
  if (ADMIN_PASSWORD_HASH) {
    try {
      return await bcrypt.compare(cleanPassword, ADMIN_PASSWORD_HASH);
    } catch {
      return false;
    }
  }
  return cleanPassword === ADMIN_PASSWORD;
}

app.post("/api/login", async (req, res) => {
  try {
    const cleanEmail = String(req.body?.email || "").trim().toLowerCase();
    const cleanPassword = String(req.body?.password || "");

    if (!cleanEmail || !cleanPassword) {
      return res.status(400).json({ ok: false, message: "email and password are required" });
    }

    if (cleanEmail === ADMIN_EMAIL) {
      const adminPasswordMatch = await isAdminPasswordValid(cleanPassword);
      if (!adminPasswordMatch) {
        return res.status(401).json({ ok: false, message: "Invalid email or password" });
      }

      return res.json({
        ok: true,
        message: "Login successful",
        admin: {
          id: "ADMIN",
          dbId: 0,
          name: ADMIN_NAME,
          email: ADMIN_EMAIL,
          accountType: "admin",
        },
      });
    }

    const [employeeRows] = await pool.query(
      "SELECT id, employee_id, name, email, password, is_blocked FROM employee WHERE email = ? LIMIT 1",
      [cleanEmail]
    );

    if (employeeRows.length) {
      const employee = employeeRows[0];
      if (Number(employee.is_blocked) === 1) {
        return res.status(403).json({
          ok: false,
          message: "Your employee account is temporarily blocked by admin.",
        });
      }
      const match = employee.password ? await bcrypt.compare(cleanPassword, employee.password) : false;
      if (match) {
        await pool.query("UPDATE employee SET login_time = CURRENT_TIMESTAMP WHERE id = ?", [
          employee.id,
        ]);

        return res.json({
          ok: true,
          message: "Login successful",
          employee: {
            id: employee.employee_id || String(employee.id),
            dbId: employee.id,
            name: employee.name,
            email: employee.email,
            accountType: "employee",
          },
        });
      }
    }

    const [companyRows] = await pool.query(
      "SELECT id, company_unique_id, company_name, email, password, is_blocked FROM company WHERE email = ? LIMIT 1",
      [cleanEmail]
    );

    if (companyRows.length) {
      const company = companyRows[0];
      if (Number(company.is_blocked) === 1) {
        return res.status(403).json({
          ok: false,
          message: "Your company account is temporarily blocked by admin.",
        });
      }
      const companyMatch = company.password ? await bcrypt.compare(cleanPassword, company.password) : false;
      if (companyMatch) {
        return res.json({
          ok: true,
          message: "Login successful",
          company: {
            id: company.company_unique_id || String(company.id),
            dbId: company.id,
            name: company.company_name,
            email: company.email,
            accountType: "company",
          },
        });
      }
    }

    return res.status(401).json({ ok: false, message: "Invalid email or password" });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
});

app.get("/api/auth/session-status", async (req, res) => {
  try {
    const accountType = String(req.query?.accountType || "").trim().toLowerCase();
    const idInput = req.query?.id;
    const emailInput = String(req.query?.email || "").trim().toLowerCase();

    if (accountType === "admin") {
      if (emailInput && emailInput !== ADMIN_EMAIL) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Admin account changed. Please login again.",
        });
      }
      return res.json({ ok: true, active: true });
    }

    if (accountType === "employee") {
      const employeeDbId = await resolveEmployeeDbId(idInput);
      if (!employeeDbId) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Employee account not found.",
        });
      }

      const [rows] = await pool.query(
        "SELECT is_blocked FROM employee WHERE id = ? LIMIT 1",
        [employeeDbId]
      );
      if (!rows.length) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Employee account not found.",
        });
      }

      if (Number(rows[0].is_blocked) === 1) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Your employee account has been blocked by admin.",
        });
      }

      return res.json({ ok: true, active: true });
    }

    if (accountType === "company") {
      const companyDbId = await resolveCompanyDbId(idInput);
      if (!companyDbId) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Company account not found.",
        });
      }

      const [rows] = await pool.query(
        "SELECT is_blocked FROM company WHERE id = ? LIMIT 1",
        [companyDbId]
      );
      if (!rows.length) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Company account not found.",
        });
      }

      if (Number(rows[0].is_blocked) === 1) {
        return res.json({
          ok: true,
          active: false,
          forceLogout: true,
          message: "Your company account has been blocked by admin.",
        });
      }

      return res.json({ ok: true, active: true });
    }

    return res.status(400).json({ ok: false, message: "Invalid account type" });
  } catch (err) {
    console.error("Session status error:", err);
    return res.status(500).json({ ok: false, message: "Failed to verify session status" });
  }
});

app.post("/api/signup/send-otp", async (req, res) => {
  try {
    const cleanEmail = String(req.body?.email || "").trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ ok: false, message: "Invalid email format" });
    }

    const [existing] = await pool.query(
      "SELECT id FROM employee WHERE email = ? LIMIT 1",
      [cleanEmail]
    );
    if (existing.length) {
      return res.status(409).json({ ok: false, message: "Email already registered" });
    }

    const [existingCompany] = await pool.query(
      "SELECT id FROM company WHERE email = ? LIMIT 1",
      [cleanEmail]
    );
    if (existingCompany.length) {
      return res.status(409).json({ ok: false, message: "Email already registered" });
    }

    const current = otpStore.get(cleanEmail);
    const now = Date.now();
    if (current && now - current.sentAt < OTP_RESEND_SECONDS * 1000) {
      return res.status(429).json({
        ok: false,
        message: `Please wait ${OTP_RESEND_SECONDS} seconds before requesting OTP again`,
      });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = now + OTP_EXPIRY_MINUTES * 60 * 1000;

    if (!transporter) {
      return res.status(500).json({
        ok: false,
        message:
          "SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, OTP_FROM_EMAIL in backend env.",
      });
    }

    await transporter.sendMail({
      from: OTP_FROM_EMAIL,
      to: cleanEmail,
      subject: "Your Signup OTP",
      text: `Your OTP is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`,
      html: `<p>Your OTP is <b>${otp}</b>.</p><p>It will expire in ${OTP_EXPIRY_MINUTES} minutes.</p>`,
    });

    otpStore.set(cleanEmail, { otp, expiresAt, sentAt: now });
    verifiedEmails.delete(cleanEmail);

    return res.json({ ok: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Send OTP error:", err);

    if (err?.code === "EAUTH") {
      return res.status(500).json({
        ok: false,
        message: "SMTP auth failed. Check SMTP_USER and SMTP_PASS (Gmail App Password).",
      });
    }

    if (err?.code === "ESOCKET" || err?.code === "ETIMEDOUT") {
      return res.status(500).json({
        ok: false,
        message: "SMTP connection failed. Check SMTP_HOST/SMTP_PORT and internet connection.",
      });
    }

    return res.status(500).json({ ok: false, message: "Failed to send OTP" });
  }
});

app.post("/api/signup/verify-otp", async (req, res) => {
  try {
    const cleanEmail = String(req.body?.email || "").trim().toLowerCase();
    const cleanOtp = String(req.body?.otp || "").trim();

    const data = otpStore.get(cleanEmail);
    if (!data) {
      return res.status(400).json({ ok: false, message: "OTP not requested for this email" });
    }

    if (Date.now() > data.expiresAt) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({ ok: false, message: "OTP expired. Please request new OTP." });
    }

    if (cleanOtp !== data.otp) {
      return res.status(400).json({ ok: false, message: "Invalid OTP" });
    }

    verifiedEmails.set(cleanEmail, Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
    otpStore.delete(cleanEmail);

    return res.json({ ok: true, message: "OTP verified" });
  } catch (err) {
    console.error("Verify OTP error:", err);
    return res.status(500).json({ ok: false, message: "Failed to verify OTP" });
  }
});

app.post(
  "/api/signup",
  upload.fields([
    { name: "panCardImage", maxCount: 1 },
    { name: "bankPassbookImage", maxCount: 1 },
    { name: "aadhaarImage", maxCount: 1 },
    { name: "photoImage", maxCount: 1 },
  ]),
  async (req, res) => {
  try {
    const { fullName, name, number, phone, mobile, email, password } = req.body || {};
    const {
      address,
      dob,
      bank_account_number,
      bankAccountNumber,
      date_of_joining,
      dateOfJoining,
      role,
    } = req.body || {};

    const cleanName = String(fullName || name || "").trim();
    const cleanNumber = String(number || phone || mobile || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPassword = String(password || "");
    const cleanAddress = String(address || "").trim();
    const cleanDob = String(dob || "").trim();
    const cleanBankAccountNumber = String(bank_account_number || bankAccountNumber || "").trim();
    const cleanDateOfJoining = String(date_of_joining || dateOfJoining || "").trim();
    const cleanRole = String(role || "").trim();

    const missingCore = [];
    if (!cleanName) missingCore.push("fullName");
    if (!cleanNumber) missingCore.push("number");
    if (!cleanEmail) missingCore.push("email");
    if (!cleanPassword) missingCore.push("password");

    if (missingCore.length) {
      return res.status(400).json({
        ok: false,
        message: `Required fields missing: ${missingCore.join(", ")}`,
      });
    }

    if (!cleanAddress || !cleanDob || !cleanBankAccountNumber || !cleanDateOfJoining || !cleanRole) {
      return res.status(400).json({
        ok: false,
        message: "address, dob, bank account number, date of joining, role are required",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ ok: false, message: "Invalid email format" });
    }

    if (!/^[0-9+\-()\s]{7,15}$/.test(cleanNumber)) {
      return res.status(400).json({
        ok: false,
        message: "Invalid number format",
      });
    }

    if (cleanPassword.length < 8) {
      return res.status(400).json({
        ok: false,
        message: "Password must be at least 8 characters",
      });
    }

    if (!/^\d{8,20}$/.test(cleanBankAccountNumber)) {
      return res.status(400).json({
        ok: false,
        message: "Bank account number must be 8-20 digits",
      });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(cleanDob) || !/^\d{4}-\d{2}-\d{2}$/.test(cleanDateOfJoining)) {
      return res.status(400).json({
        ok: false,
        message: "DOB and date of joining must be valid date format (YYYY-MM-DD)",
      });
    }

    const panCardImage = req.files?.panCardImage?.[0] || null;
    const bankPassbookImage = req.files?.bankPassbookImage?.[0] || null;
    const aadhaarImage = req.files?.aadhaarImage?.[0] || null;
    const photoImage = req.files?.photoImage?.[0] || null;

    if (!panCardImage || !bankPassbookImage || !aadhaarImage || !photoImage) {
      return res.status(400).json({
        ok: false,
        message: "PAN, bank passbook, Aadhaar and photo images are required",
      });
    }

    const imageFiles = [panCardImage, bankPassbookImage, aadhaarImage, photoImage];
    for (const file of imageFiles) {
      const isImage = /^image\//i.test(String(file.mimetype || ""));
      if (!isImage) {
        return res.status(400).json({
          ok: false,
          message: "Only image files are allowed for PAN/Aadhaar/Photo/Passbook",
        });
      }
      if (Number(file.size || 0) > EMPLOYEE_IMAGE_MAX_BYTES) {
        return res.status(400).json({
          ok: false,
          message: `Each image must be 100KB or smaller. Failed: ${file.originalname || "image file"}`,
        });
      }
    }

    if (!isDriveConfigured()) {
      return res.status(500).json({
        ok: false,
        message:
          "Google Drive is not configured. Set Google auth env values and target folder id in backend env.",
      });
    }

    const verifiedUntil = verifiedEmails.get(cleanEmail);
    if (!verifiedUntil || Date.now() > verifiedUntil) {
      verifiedEmails.delete(cleanEmail);
      return res.status(400).json({
        ok: false,
        message: "Email not verified. Please verify OTP first.",
      });
    }

    const [existing] = await pool.query("SELECT id FROM employee WHERE email = ? LIMIT 1", [cleanEmail]);
    if (existing.length) {
      return res.status(409).json({ ok: false, message: "Email already registered" });
    }

    const safeSaltRounds =
      Number.isInteger(BCRYPT_SALT_ROUNDS) && BCRYPT_SALT_ROUNDS >= 4 && BCRYPT_SALT_ROUNDS <= 15
        ? BCRYPT_SALT_ROUNDS
        : 10;
    const passwordHash = await bcrypt.hash(cleanPassword, safeSaltRounds);
    const employeeId = await generateUniqueEmployeeId();
    const folderName = sanitizeDriveName(`${cleanName}-${employeeId}`);
    const termsList = normalizeTermsPoints("");

    const { folderId } = await ensureDriveFolder({
      parentId: EMPLOYEE_DRIVE_ROOT_FOLDER_ID,
      folderName,
    });

    const [panUploaded, passbookUploaded, aadhaarUploaded, photoUploaded] = await Promise.all([
      uploadBinaryToDrive({
        parentId: folderId,
        fileBuffer: panCardImage.buffer,
        fileName: "pan-card.jpg",
        mimeType: panCardImage.mimetype,
      }),
      uploadBinaryToDrive({
        parentId: folderId,
        fileBuffer: bankPassbookImage.buffer,
        fileName: "bank-passbook.jpg",
        mimeType: bankPassbookImage.mimetype,
      }),
      uploadBinaryToDrive({
        parentId: folderId,
        fileBuffer: aadhaarImage.buffer,
        fileName: "aadhaar.jpg",
        mimeType: aadhaarImage.mimetype,
      }),
      uploadBinaryToDrive({
        parentId: folderId,
        fileBuffer: photoImage.buffer,
        fileName: "photo.jpg",
        mimeType: photoImage.mimetype,
      }),
    ]);

    const pdfBuffer = await buildEmployeeProfilePdfBuffer({
      employeeId,
      form: {
        fullName: cleanName,
        number: cleanNumber,
        email: cleanEmail,
        address: cleanAddress,
        dob: cleanDob,
        bankAccountNumber: cleanBankAccountNumber,
        dateOfJoining: cleanDateOfJoining,
        role: cleanRole,
      },
      termsPoints: termsList,
      imageLinks: {
        panCardLink: panUploaded.viewLink,
        bankPassbookLink: passbookUploaded.viewLink,
        aadhaarLink: aadhaarUploaded.viewLink,
        photoLink: photoUploaded.viewLink,
      },
      imageBuffers: {
        panCardImage: panCardImage.buffer,
        bankPassbookImage: bankPassbookImage.buffer,
        aadhaarImage: aadhaarImage.buffer,
        photoImage: photoImage.buffer,
      },
    });

    const pdfUploaded = await uploadBinaryToDrive({
      parentId: folderId,
      fileBuffer: pdfBuffer,
      fileName: `${folderName}-profile.pdf`,
      mimeType: "application/pdf",
    });

    const [result] = await pool.query(
      `INSERT INTO employee (
        employee_id, name, number, email, password, address, dob, pan_card_link,
        bank_account_number, bank_passbook_link, aadhaar_link, photo_link, date_of_joining, role,
        terms_points, profile_pdf_link, profile_folder_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        employeeId,
        cleanName,
        cleanNumber,
        cleanEmail,
        passwordHash,
        cleanAddress,
        cleanDob,
        panUploaded.viewLink,
        cleanBankAccountNumber,
        passbookUploaded.viewLink,
        aadhaarUploaded.viewLink,
        photoUploaded.viewLink,
        cleanDateOfJoining,
        cleanRole,
        JSON.stringify(termsList),
        pdfUploaded.viewLink,
        folderId,
      ]
    );

    verifiedEmails.delete(cleanEmail);

    return res.status(201).json({
      ok: true,
      message: "Signup successful",
      employee: {
        id: employeeId,
        dbId: result.insertId,
        name: cleanName,
        number: cleanNumber,
        email: cleanEmail,
        pdfTemplate: "employee-v2-images",
        profileFolderId: folderId,
        profilePdfLink: pdfUploaded.viewLink,
        docs: {
          panCardLink: panUploaded.viewLink,
          bankPassbookLink: passbookUploaded.viewLink,
          aadhaarLink: aadhaarUploaded.viewLink,
          photoLink: photoUploaded.viewLink,
        },
      },
    });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ ok: false, message: "Email already registered" });
    }

    if (err && err.code === "ER_BAD_FIELD_ERROR") {
      return res.status(500).json({
        ok: false,
        message: "Database schema mismatch. Restart backend so table migration can run.",
      });
    }

    console.error("Signup error:", err);
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
}
);

app.post("/api/company/signup", upload.single("panCardImage"), async (req, res) => {
  try {
    const body = req.body || {};
    const cleanCompanyName = String(body.company_name || body.companyName || "").trim();
    const cleanTradeName = String(body.trade_name || body.tradeName || "").trim();
    const cleanBusinessType = String(body.business_type || body.businessType || "").trim();
    const cleanGst = String(body.gst_number || body.gstNumber || "").trim().toUpperCase();
    const cleanPan = String(body.pan_number || body.panNumber || "").trim().toUpperCase();
    const cleanCin = String(body.cin_number || body.cinNumber || "").trim().toUpperCase();
    const cleanRegisteredAddress = String(
      body.registered_address || body.registeredAddress || ""
    ).trim();
    const cleanOperationalAddress = String(
      body.operational_address || body.operationalAddress || ""
    ).trim();
    const cleanContactName = String(
      body.contact_full_name || body.contactFullName || ""
    ).trim();
    const cleanMobile = String(body.mobile_number || body.mobileNumber || "").trim();
    const cleanEmail = String(body.email || "").trim().toLowerCase();
    const cleanPassword = String(body.password || "").trim();

    const missing = [];
    if (!cleanCompanyName) missing.push("company_name");
    if (!cleanBusinessType) missing.push("business_type");
    if (!cleanGst) missing.push("gst_number");
    if (!cleanPan) missing.push("pan_number");
    if (!cleanCin) missing.push("cin_number");
    if (!cleanRegisteredAddress) missing.push("registered_address");
    if (!cleanOperationalAddress) missing.push("operational_address");
    if (!cleanContactName) missing.push("contact_full_name");
    if (!cleanMobile) missing.push("mobile_number");
    if (!cleanEmail) missing.push("email");
    if (!cleanPassword) missing.push("password");

    if (missing.length) {
      return res.status(400).json({
        ok: false,
        message: `Required fields missing: ${missing.join(", ")}`,
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ ok: false, message: "Invalid email format" });
    }

    if (!GSTIN_REGEX.test(cleanGst)) {
      return res.status(400).json({ ok: false, message: "Invalid GSTIN format" });
    }

    if (!PAN_REGEX.test(cleanPan)) {
      return res.status(400).json({ ok: false, message: "Invalid PAN format" });
    }

    if (!CIN_REGEX.test(cleanCin)) {
      return res.status(400).json({ ok: false, message: "Invalid CIN format" });
    }

    if (!/^[0-9+\-()\s]{7,15}$/.test(cleanMobile)) {
      return res.status(400).json({ ok: false, message: "Invalid mobile number format" });
    }

    if (cleanPassword.length < 8) {
      return res.status(400).json({ ok: false, message: "Password must be at least 8 characters" });
    }

    const panCardImage = req.file && req.file.buffer ? req.file : null;
    if (panCardImage && !/^image\//i.test(String(panCardImage.mimetype || ""))) {
      return res.status(400).json({ ok: false, message: "PAN card must be an image file" });
    }
    if (!panCardImage) {
      return res.status(400).json({
        ok: false,
        message: "PAN card image is required",
      });
    }

    if (!isDriveConfigured()) {
      return res.status(500).json({
        ok: false,
        message:
          "Google Drive is not configured. Set Google auth env values and target folder id in backend env.",
      });
    }

    const verifiedUntil = verifiedEmails.get(cleanEmail);
    if (!verifiedUntil || Date.now() > verifiedUntil) {
      verifiedEmails.delete(cleanEmail);
      return res.status(400).json({
        ok: false,
        message: "Email not verified. Please verify OTP first.",
      });
    }

    const [existingCompany] = await pool.query("SELECT id FROM company WHERE email = ? LIMIT 1", [
      cleanEmail,
    ]);
    if (existingCompany.length) {
      return res.status(409).json({ ok: false, message: "Company email already registered" });
    }

    const [existingEmployee] = await pool.query("SELECT id FROM employee WHERE email = ? LIMIT 1", [
      cleanEmail,
    ]);
    if (existingEmployee.length) {
      return res.status(409).json({ ok: false, message: "Email already used by employee account" });
    }

    const companyUniqueId = await generateUniqueCompanyId();
    const safeSaltRounds =
      Number.isInteger(BCRYPT_SALT_ROUNDS) && BCRYPT_SALT_ROUNDS >= 4 && BCRYPT_SALT_ROUNDS <= 15
        ? BCRYPT_SALT_ROUNDS
        : 10;
    const passwordHash = await bcrypt.hash(cleanPassword, safeSaltRounds);
    const folderName = sanitizeDriveName(`${cleanCompanyName}-${companyUniqueId}`);
    const { folderId } = await ensureDriveFolder({
      parentId: COMPANY_DRIVE_ROOT_FOLDER_ID,
      folderName,
    });

    const panUploaded = await uploadBinaryToDrive({
      parentId: folderId,
      fileBuffer: panCardImage.buffer,
      fileName: "pan-card.jpg",
      mimeType: panCardImage.mimetype,
    });
    const panCardDriveLink = panUploaded.viewLink;

    const companyPdfBuffer = await buildCompanyProfilePdfBuffer({
      companyId: companyUniqueId,
      form: {
        companyName: cleanCompanyName,
        tradeName: cleanTradeName,
        businessType: cleanBusinessType,
        gstNumber: cleanGst,
        panNumber: cleanPan,
        cinNumber: cleanCin,
        registeredAddress: cleanRegisteredAddress,
        operationalAddress: cleanOperationalAddress,
        contactFullName: cleanContactName,
        mobileNumber: cleanMobile,
        email: cleanEmail,
      },
      panCardImageBuffer: panCardImage ? panCardImage.buffer : null,
    });

    const pdfUploaded = await uploadBinaryToDrive({
      parentId: folderId,
      fileBuffer: companyPdfBuffer,
      fileName: `${folderName}-profile.pdf`,
      mimeType: "application/pdf",
    });

    const [result] = await pool.query(
      `INSERT INTO company (
        company_unique_id, company_name, trade_name, business_type, gst_number, pan_number,
        pan_card_link, cin_number, registered_address, operational_address, contact_full_name,
        mobile_number, email, password, profile_pdf_link, profile_folder_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        companyUniqueId,
        cleanCompanyName,
        cleanTradeName || null,
        cleanBusinessType,
        cleanGst,
        cleanPan,
        panCardDriveLink,
        cleanCin,
        cleanRegisteredAddress,
        cleanOperationalAddress,
        cleanContactName,
        cleanMobile,
        cleanEmail,
        passwordHash,
        pdfUploaded.viewLink,
        folderId,
      ]
    );

    verifiedEmails.delete(cleanEmail);

    return res.status(201).json({
      ok: true,
      message: "Company signup successful",
      company: {
        id: companyUniqueId,
        dbId: result.insertId,
        company_name: cleanCompanyName,
        contact_full_name: cleanContactName,
        mobile_number: cleanMobile,
        email: cleanEmail,
        profileFolderId: folderId,
        profilePdfLink: pdfUploaded.viewLink,
        pan_card_link: panCardDriveLink,
        pan_card_drive_link: panCardDriveLink,
      },
    });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ ok: false, message: "Company already exists with this email or ID" });
    }
    console.error("Company signup error:", err);
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
});

app.get("/api/companies/consignors", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT company_name, business_type
       FROM company
       WHERE company_name IS NOT NULL
         AND TRIM(company_name) <> ''
       ORDER BY created_at DESC, id DESC`
    );

    const seen = new Set();
    const companies = [];
    for (const row of rows) {
      const companyName = String(row?.company_name || "").trim();
      if (!companyName) continue;

      const normalizedName = companyName.toLowerCase();
      if (seen.has(normalizedName)) continue;
      seen.add(normalizedName);

      companies.push({
        company_name: companyName,
        business_type: String(row?.business_type || "").trim(),
      });
    }

    return res.json({ ok: true, companies });
  } catch (err) {
    console.error("Fetch consignor companies error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch consignor companies" });
  }
});

app.get("/api/admin/overview", async (req, res) => {
  try {
    if (!isAdminAuthorized(req)) {
      return res.status(401).json({ ok: false, message: "Unauthorized admin request" });
    }

    const [employeeRows] = await pool.query(
      `SELECT id, employee_id, name, number, email, login_time, address, dob, pan_card_link,
              bank_account_number, bank_passbook_link, aadhaar_link, photo_link,
              date_of_joining, role, terms_points, profile_pdf_link, profile_folder_id,
              is_blocked, blocked_at
       FROM employee
       ORDER BY id DESC`
    );

    const [employeeDocsRows] = await pool.query(
      `SELECT id, employee_id, awb_no, form_type, created_at, pdf_link
       FROM employee_docs
       ORDER BY created_at DESC, id DESC`
    );

    const docsByEmployeeDbId = new Map();
    for (const doc of employeeDocsRows) {
      const key = Number(doc.employee_id);
      const existing = docsByEmployeeDbId.get(key) || [];
      existing.push(doc);
      docsByEmployeeDbId.set(key, existing);
    }

    const employees = employeeRows.map((row) => {
      const rawTerms = String(row.terms_points || "").trim();
      let termsPoints = [];
      if (rawTerms) {
        try {
          const parsed = JSON.parse(rawTerms);
          termsPoints = Array.isArray(parsed) ? parsed : [];
        } catch {
          termsPoints = [];
        }
      }

      return {
        ...row,
        is_blocked: Number(row.is_blocked) === 1,
        terms_points: termsPoints,
        docs: docsByEmployeeDbId.get(Number(row.id)) || [],
      };
    });

    const [companyRows] = await pool.query(
      `SELECT id, company_unique_id, company_name, trade_name, business_type,
              gst_number, pan_number, pan_card_link, cin_number,
              registered_address, operational_address, contact_full_name,
              mobile_number, email, profile_pdf_link, profile_folder_id,
              created_at, is_blocked, blocked_at
       FROM company
       ORDER BY id DESC`
    );

    const [allDocsRows] = await pool.query(
      `SELECT d.id, d.employee_id, d.awb_no, d.form_type, d.created_at, d.pdf_link,
              e.name AS generated_by_name,
              e.employee_id AS generated_by_employee_id,
              COALESCE(
                ab.consignor_name,
                CASE
                  WHEN JSON_VALID(d.form_data) THEN JSON_UNQUOTE(JSON_EXTRACT(d.form_data, '$.form.consignor'))
                  ELSE NULL
                END
              ) AS consignor_name
       FROM employee_docs d
       LEFT JOIN employee e ON e.id = d.employee_id
       LEFT JOIN airwaybills ab ON ab.awb_number = d.awb_no
       ORDER BY d.created_at DESC, d.id DESC`
    );

    const companyDocsByName = new Map();
    for (const doc of allDocsRows) {
      const consignorName = String(doc.consignor_name || "").trim().toLowerCase();
      if (!consignorName) continue;
      const existing = companyDocsByName.get(consignorName) || [];
      existing.push(doc);
      companyDocsByName.set(consignorName, existing);
    }

    const companies = companyRows.map((row) => {
      const docs = companyDocsByName.get(String(row.company_name || "").trim().toLowerCase()) || [];
      return {
        ...row,
        is_blocked: Number(row.is_blocked) === 1,
        docs,
      };
    });

    return res.json({
      ok: true,
      employees,
      companies,
    });
  } catch (err) {
    console.error("Admin overview error:", err);
    return res.status(500).json({ ok: false, message: "Failed to load admin overview" });
  }
});

app.patch("/api/admin/employee/:id/block", async (req, res) => {
  try {
    if (!isAdminAuthorized(req)) {
      return res.status(401).json({ ok: false, message: "Unauthorized admin request" });
    }

    const employeeDbId = await resolveEmployeeDbId(req.params?.id);
    if (!employeeDbId) {
      return res.status(400).json({ ok: false, message: "Invalid employee id" });
    }

    const [rows] = await pool.query(
      "SELECT id, employee_id, name, email, is_blocked FROM employee WHERE id = ? LIMIT 1",
      [employeeDbId]
    );

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: "Employee not found" });
    }

    const currentBlocked = Number(rows[0].is_blocked) === 1;
    const inputBlocked = parseOptionalBoolean(req.body?.blocked);
    const nextBlocked = inputBlocked === null ? !currentBlocked : inputBlocked;

    await pool.query(
      `UPDATE employee
       SET is_blocked = ?, blocked_at = ?
       WHERE id = ?`,
      [nextBlocked ? 1 : 0, nextBlocked ? new Date() : null, employeeDbId]
    );

    return res.json({
      ok: true,
      message: nextBlocked ? "Employee blocked successfully" : "Employee unblocked successfully",
      employee: {
        id: rows[0].employee_id || String(rows[0].id),
        dbId: rows[0].id,
        name: rows[0].name,
        email: rows[0].email,
        is_blocked: nextBlocked,
      },
    });
  } catch (err) {
    console.error("Employee block/unblock error:", err);
    return res.status(500).json({ ok: false, message: "Failed to update employee status" });
  }
});

app.patch("/api/admin/company/:id/block", async (req, res) => {
  try {
    if (!isAdminAuthorized(req)) {
      return res.status(401).json({ ok: false, message: "Unauthorized admin request" });
    }

    const companyDbId = await resolveCompanyDbId(req.params?.id);
    if (!companyDbId) {
      return res.status(400).json({ ok: false, message: "Invalid company id" });
    }

    const [rows] = await pool.query(
      "SELECT id, company_unique_id, company_name, email, is_blocked FROM company WHERE id = ? LIMIT 1",
      [companyDbId]
    );

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: "Company not found" });
    }

    const currentBlocked = Number(rows[0].is_blocked) === 1;
    const inputBlocked = parseOptionalBoolean(req.body?.blocked);
    const nextBlocked = inputBlocked === null ? !currentBlocked : inputBlocked;

    await pool.query(
      `UPDATE company
       SET is_blocked = ?, blocked_at = ?
       WHERE id = ?`,
      [nextBlocked ? 1 : 0, nextBlocked ? new Date() : null, companyDbId]
    );

    return res.json({
      ok: true,
      message: nextBlocked ? "Company blocked successfully" : "Company unblocked successfully",
      company: {
        id: rows[0].company_unique_id || String(rows[0].id),
        dbId: rows[0].id,
        name: rows[0].company_name,
        email: rows[0].email,
        is_blocked: nextBlocked,
      },
    });
  } catch (err) {
    console.error("Company block/unblock error:", err);
    return res.status(500).json({ ok: false, message: "Failed to update company status" });
  }
});

app.get("/api/admin/docs/daily", async (req, res) => {
  try {
    if (!isAdminAuthorized(req)) {
      return res.status(401).json({ ok: false, message: "Unauthorized admin request" });
    }

    const inputDate = String(req.query?.date || "").trim();
    const targetDate = /^\d{4}-\d{2}-\d{2}$/.test(inputDate)
      ? inputDate
      : new Date().toISOString().slice(0, 10);

    const [rows] = await pool.query(
      `SELECT d.id, d.employee_id, d.awb_no, d.form_type, d.created_at, d.pdf_link,
              e.name AS generated_by_name,
              e.employee_id AS generated_by_employee_id
       FROM employee_docs d
       LEFT JOIN employee e ON e.id = d.employee_id
       WHERE d.form_type = 'Doct' AND DATE(d.created_at) = ?
       ORDER BY d.created_at DESC, d.id DESC`,
      [targetDate]
    );

    const docs = rows.map((row) => ({
      ...row,
      edit_url: `/doct?docId=${encodeURIComponent(row.id)}&employeeId=${encodeURIComponent(
        row.employee_id
      )}&admin=1`,
    }));

    return res.json({
      ok: true,
      date: targetDate,
      total: docs.length,
      docs,
    });
  } catch (err) {
    console.error("Admin daily docs error:", err);
    return res.status(500).json({ ok: false, message: "Failed to load daily doct documents" });
  }
});

app.post("/api/docs/next-awb", async (req, res) => {
  try {
    const formType = req.body?.formType === "Manifest" ? "Manifest" : "Doct";
    const consignor = String(req.body?.consignor || "").trim();
    const employeeIdInput = req.body?.employeeId;

    if (!consignor) {
      return res.status(400).json({ ok: false, message: "consignor is required" });
    }

    let employeeDbId = null;
    if (employeeIdInput !== undefined && employeeIdInput !== null && String(employeeIdInput).trim()) {
      employeeDbId = await resolveEmployeeDbId(employeeIdInput);
      if (!employeeDbId) {
        return res.status(400).json({ ok: false, message: "Invalid employee id" });
      }
    }

    const allocated = await allocateNextAwb({
      formType,
      consignor,
      employeeDbId,
    });

    return res.status(201).json({
      ok: true,
      message: "AWB number generated",
      awb: allocated,
    });
  } catch (err) {
    console.error("Generate AWB error:", err);
    return res.status(500).json({ ok: false, message: "Failed to generate AWB number" });
  }
});

app.post("/api/docs", async (req, res) => {
  try {
    const employeeDbId = await resolveEmployeeDbId(req.body?.employeeId);
    const docId = Number(req.body?.docId || 0);
    const awbNo = String(req.body?.awbNo || "").trim();
    const formType = req.body?.formType === "Manifest" ? "Manifest" : "Doct";
    const pdfLink = req.body?.pdfLink ? String(req.body.pdfLink) : null;
    const rawFormData =
      req.body?.formData && typeof req.body.formData === "object" ? req.body.formData : null;
    const consignorName = String(rawFormData?.form?.consignor || "").trim() || null;
    const formData = rawFormData ? JSON.stringify(rawFormData) : null;

    if (!employeeDbId) {
      return res.status(400).json({ ok: false, message: "Invalid employee id" });
    }

    if (!awbNo) {
      return res.status(400).json({ ok: false, message: "awbNo is required" });
    }

    if (docId > 0) {
      await pool.query(
        `UPDATE employee_docs
         SET awb_no = ?, form_type = ?, pdf_link = ?, form_data = ?
         WHERE id = ? AND employee_id = ?`,
        [awbNo, formType, pdfLink, formData, docId, employeeDbId]
      );

      if (pdfLink) {
        await pool.query(
          `INSERT INTO airwaybills (awb_number, consignor_name, pdf_link)
           VALUES (?, ?, ?)
           ON DUPLICATE KEY UPDATE
             consignor_name = COALESCE(VALUES(consignor_name), airwaybills.consignor_name),
             pdf_link = VALUES(pdf_link)`,
          [awbNo, consignorName, pdfLink]
        );
      }

      return res.status(200).json({
        ok: true,
        message: "Document updated",
        doc: {
          id: docId,
          employee_id: employeeDbId,
          awb_no: awbNo,
          form_type: formType,
          pdf_link: pdfLink,
        },
      });
    }

    const [result] = await pool.query(
      `INSERT INTO employee_docs (employee_id, awb_no, form_type, pdf_link, form_data)
       VALUES (?, ?, ?, ?, ?)`,
      [employeeDbId, awbNo, formType, pdfLink, formData]
    );

    if (pdfLink) {
      await pool.query(
        `INSERT INTO airwaybills (awb_number, consignor_name, pdf_link)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           consignor_name = COALESCE(VALUES(consignor_name), airwaybills.consignor_name),
           pdf_link = VALUES(pdf_link)`,
        [awbNo, consignorName, pdfLink]
      );
    }

    return res.status(201).json({
      ok: true,
      message: "Document saved",
      doc: {
        id: result.insertId,
        employee_id: employeeDbId,
        awb_no: awbNo,
        form_type: formType,
        pdf_link: pdfLink,
      },
    });
  } catch (err) {
    console.error("Save doc error:", err);
    return res.status(500).json({ ok: false, message: "Failed to save document" });
  }
});

app.get("/api/docs", async (req, res) => {
  try {
    const employeeDbId = await resolveEmployeeDbId(req.query?.employeeId);
    if (!employeeDbId) {
      return res.status(400).json({ ok: false, message: "Invalid employee id" });
    }

    const [rows] = await pool.query(
      `SELECT id, employee_id, awb_no, form_type, created_at, pdf_link
       FROM employee_docs
       WHERE employee_id = ?
       ORDER BY created_at DESC, id DESC`,
      [employeeDbId]
    );

    return res.json({ ok: true, docs: rows });
  } catch (err) {
    console.error("Fetch docs error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch documents" });
  }
});

app.get("/api/company/docs", async (req, res) => {
  try {
    const companyIdInput = req.query?.companyId;
    if (companyIdInput === undefined || companyIdInput === null || !String(companyIdInput).trim()) {
      return res.status(400).json({ ok: false, message: "companyId is required" });
    }

    const companyDbId = await resolveCompanyDbId(companyIdInput);
    if (!companyDbId) {
      return res.status(400).json({ ok: false, message: "Invalid company id" });
    }

    const [companyRows] = await pool.query(
      "SELECT company_name FROM company WHERE id = ? LIMIT 1",
      [companyDbId]
    );
    if (!companyRows.length) {
      return res.status(404).json({ ok: false, message: "Company not found" });
    }
    const companyName = String(companyRows[0].company_name || "").trim();
    if (!companyName) {
      return res.json({ ok: true, docs: [] });
    }

    const [rows] = await pool.query(
      `SELECT d.id, d.employee_id, d.awb_no, d.form_type, d.created_at, d.pdf_link,
              e.name AS generated_by_name,
              e.employee_id AS generated_by_employee_id,
              ab.consignor_name,
              'employee' AS generated_by_type
       FROM employee_docs d
       LEFT JOIN employee e ON e.id = d.employee_id
       LEFT JOIN airwaybills ab ON ab.awb_number = d.awb_no
       WHERE LOWER(TRIM(COALESCE(
         ab.consignor_name,
         CASE
           WHEN JSON_VALID(d.form_data) THEN JSON_UNQUOTE(JSON_EXTRACT(d.form_data, '$.form.consignor'))
           ELSE NULL
         END,
         ''
       ))) = LOWER(TRIM(?))
       ORDER BY d.created_at DESC, d.id DESC`
      ,
      [companyName]
    );

    return res.json({ ok: true, docs: rows });
  } catch (err) {
    console.error("Fetch company docs error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch company documents" });
  }
});

app.get("/api/docs/:id", async (req, res) => {
  try {
    const employeeDbId = await resolveEmployeeDbId(req.query?.employeeId);
    const docId = Number(req.params?.id || 0);
    if (!employeeDbId || !docId) {
      return res.status(400).json({ ok: false, message: "Invalid employee id or doc id" });
    }

    const [rows] = await pool.query(
      `SELECT id, employee_id, awb_no, form_type, created_at, pdf_link, form_data
       FROM employee_docs
       WHERE id = ? AND employee_id = ?
       LIMIT 1`,
      [docId, employeeDbId]
    );

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: "Document not found" });
    }

    const row = rows[0];
    let parsedFormData = null;
    if (row.form_data) {
      try {
        parsedFormData = JSON.parse(row.form_data);
      } catch {
        parsedFormData = null;
      }
    }

    return res.json({
      ok: true,
      doc: {
        ...row,
        form_data: parsedFormData,
      },
    });
  } catch (err) {
    console.error("Fetch doc by id error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch document" });
  }
});

async function start() {
  try {
    await ensureEmployeeTable();
    console.log("employee table is ready");
    await ensureEmployeeDocsTable();
    console.log("employee_docs table is ready");
    await ensureAirwayBillsTable();
    console.log("airwaybills table is ready");
    await ensureCompanyTable();
    console.log("company table is ready");
  } catch (err) {
    console.error("Could not ensure employee table:", err.message);
  }

  app.listen(PORT, HOST, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Network URL: http://<your-ip>:${PORT}`);
  });
}

start();
