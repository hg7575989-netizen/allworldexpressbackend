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
const DB_URL = String(process.env.DATABASE_URL || process.env.MYSQL_URL || "").trim();
const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_USER = process.env.DB_USER || "root";
const DB_PASSWORD = process.env.DB_PASSWORD || "1234";
const DB_NAME = process.env.DB_NAME || "courier_app";
const DB_SSL = ["1", "true", "yes"].includes(String(process.env.DB_SSL || "").trim().toLowerCase());
const DB_SSL_REJECT_UNAUTHORIZED = !["0", "false", "no"].includes(
  String(process.env.DB_SSL_REJECT_UNAUTHORIZED || "").trim().toLowerCase()
);
const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES || 10);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 30);
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);

const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = String(process.env.SMTP_PASS || "").replace(/\s+/g, "");
const OTP_FROM_EMAIL = process.env.OTP_FROM_EMAIL || SMTP_USER;
const OTP_FROM_NAME = String(process.env.OTP_FROM_NAME || "AllWorld Express").trim();
const BREVO_API_KEY = String(process.env.BREVO_API_KEY || "").trim();
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
const IS_RENDER = String(process.env.RENDER || "").toLowerCase() === "true";

if (IS_RENDER && (!process.env.DB_HOST || DB_HOST === "127.0.0.1" || DB_HOST === "localhost")) {
  console.warn(
    "DB_HOST is pointing to localhost on Render. Set external MySQL credentials in Render Environment variables."
  );
}

const poolConfig = {
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

if (DB_SSL) {
  poolConfig.ssl = { rejectUnauthorized: DB_SSL_REJECT_UNAUTHORIZED };
}

if (DB_URL) {
  poolConfig.uri = DB_URL;
  if (IS_RENDER) {
    console.log("Using DATABASE_URL/MYSQL_URL for MySQL connection.");
  }
} else {
  poolConfig.host = DB_HOST;
  poolConfig.port = DB_PORT;
  poolConfig.user = DB_USER;
  poolConfig.password = DB_PASSWORD;
  poolConfig.database = DB_NAME;
}

const pool = mysql.createPool(poolConfig);

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

async function sendOtpEmail({ to, otp }) {
  const subject = "Your Signup OTP";
  const text = `Your OTP is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`;
  const html = `<p>Your OTP is <b>${otp}</b>.</p><p>It will expire in ${OTP_EXPIRY_MINUTES} minutes.</p>`;

  if (BREVO_API_KEY) {
    if (!OTP_FROM_EMAIL) {
      const err = new Error("Brevo sender email is missing");
      err.code = "BREVO_SENDER_MISSING";
      throw err;
    }

    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "api-key": BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: {
          name: OTP_FROM_NAME,
          email: OTP_FROM_EMAIL,
        },
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html,
      }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      const err = new Error(data?.message || "Brevo email send failed");
      err.code = response.status === 401 || response.status === 403 ? "BREVO_AUTH" : "BREVO_SEND";
      err.status = response.status;
      err.providerMessage = data?.message || "";
      throw err;
    }

    return;
  }

  if (!transporter) {
    const err = new Error("SMTP is not configured");
    err.code = "EMAIL_NOT_CONFIGURED";
    throw err;
  }

  await transporter.sendMail({
    from: OTP_FROM_EMAIL,
    to,
    subject,
    text,
    html,
  });
}

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
      employee_id INT NULL,
      generated_by_type ENUM('employee','self','admin') NOT NULL DEFAULT 'employee',
      generated_by_company_id INT NULL,
      generated_by_company_name VARCHAR(200) NULL,
      generated_by_admin_name VARCHAR(120) NULL,
      awb_no VARCHAR(120) NOT NULL,
      form_type ENUM('Doct','Manifest') NOT NULL DEFAULT 'Doct',
      order_status ENUM('processing','manifest','in_transit','out_for_delivery','delivered') NOT NULL DEFAULT 'processing',
      manifest_number VARCHAR(20) NULL,
      manifest_to_name VARCHAR(200) NULL,
      manifest_destination VARCHAR(200) NULL,
      manifest_date DATE NULL,
      manifest_through VARCHAR(200) NULL,
      last_scan_latitude DECIMAL(10,7) NULL,
      last_scan_longitude DECIMAL(10,7) NULL,
      last_scan_ip VARCHAR(120) NULL,
      last_scan_at DATETIME NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      pdf_link TEXT NULL,
      form_data LONGTEXT NULL,
      KEY idx_employee_docs_employee_id (employee_id),
      KEY idx_employee_docs_generated_by_company_id (generated_by_company_id),
      KEY idx_employee_docs_order_status (order_status),
      CONSTRAINT fk_employee_docs_employee
        FOREIGN KEY (employee_id) REFERENCES employee(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
    ) ENGINE=InnoDB;
  `;

  await pool.query(sql);

  const [employeeIdNullability] = await pool.query(
    `SELECT IS_NULLABLE
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND COLUMN_NAME = 'employee_id'
     LIMIT 1`,
    [DB_NAME]
  );
  if (employeeIdNullability.length && String(employeeIdNullability[0].IS_NULLABLE || "").toUpperCase() !== "YES") {
    await pool.query("ALTER TABLE employee_docs MODIFY COLUMN employee_id INT NULL");
  }

  const employeeDocColumns = [
    [
      "generated_by_type",
      "ALTER TABLE employee_docs ADD COLUMN generated_by_type ENUM('employee','self','admin') NOT NULL DEFAULT 'employee' AFTER employee_id",
    ],
    [
      "generated_by_company_id",
      "ALTER TABLE employee_docs ADD COLUMN generated_by_company_id INT NULL AFTER generated_by_type",
    ],
    [
      "generated_by_company_name",
      "ALTER TABLE employee_docs ADD COLUMN generated_by_company_name VARCHAR(200) NULL AFTER generated_by_company_id",
    ],
    [
      "generated_by_admin_name",
      "ALTER TABLE employee_docs ADD COLUMN generated_by_admin_name VARCHAR(120) NULL AFTER generated_by_company_name",
    ],
    [
      "order_status",
      "ALTER TABLE employee_docs ADD COLUMN order_status ENUM('processing','manifest','in_transit','out_for_delivery','delivered') NOT NULL DEFAULT 'processing' AFTER form_type",
    ],
    [
      "manifest_number",
      "ALTER TABLE employee_docs ADD COLUMN manifest_number VARCHAR(20) NULL AFTER order_status",
    ],
    [
      "manifest_to_name",
      "ALTER TABLE employee_docs ADD COLUMN manifest_to_name VARCHAR(200) NULL AFTER manifest_number",
    ],
    [
      "manifest_destination",
      "ALTER TABLE employee_docs ADD COLUMN manifest_destination VARCHAR(200) NULL AFTER manifest_to_name",
    ],
    [
      "manifest_date",
      "ALTER TABLE employee_docs ADD COLUMN manifest_date DATE NULL AFTER manifest_destination",
    ],
    [
      "manifest_through",
      "ALTER TABLE employee_docs ADD COLUMN manifest_through VARCHAR(200) NULL AFTER manifest_date",
    ],
    [
      "last_scan_latitude",
      "ALTER TABLE employee_docs ADD COLUMN last_scan_latitude DECIMAL(10,7) NULL AFTER manifest_through",
    ],
    [
      "last_scan_longitude",
      "ALTER TABLE employee_docs ADD COLUMN last_scan_longitude DECIMAL(10,7) NULL AFTER last_scan_latitude",
    ],
    [
      "last_scan_ip",
      "ALTER TABLE employee_docs ADD COLUMN last_scan_ip VARCHAR(120) NULL AFTER last_scan_longitude",
    ],
    [
      "last_scan_at",
      "ALTER TABLE employee_docs ADD COLUMN last_scan_at DATETIME NULL AFTER last_scan_ip",
    ],
  ];
  for (const [columnName, ddl] of employeeDocColumns) {
    const [exists] = await pool.query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND COLUMN_NAME = ?
       LIMIT 1`,
      [DB_NAME, columnName]
    );
    if (!exists.length) {
      await pool.query(ddl);
    }
  }

  const [generatedByTypeColumn] = await pool.query(
    `SELECT COLUMN_TYPE
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND COLUMN_NAME = 'generated_by_type'
     LIMIT 1`,
    [DB_NAME]
  );
  if (
    generatedByTypeColumn.length &&
    !String(generatedByTypeColumn[0].COLUMN_TYPE || "").toLowerCase().includes("'admin'")
  ) {
    await pool.query(
      "ALTER TABLE employee_docs MODIFY COLUMN generated_by_type ENUM('employee','self','admin') NOT NULL DEFAULT 'employee'"
    );
  }

  const [companyGenIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND INDEX_NAME = 'idx_employee_docs_generated_by_company_id'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!companyGenIndex.length) {
    await pool.query(
      "CREATE INDEX idx_employee_docs_generated_by_company_id ON employee_docs (generated_by_company_id)"
    );
  }

  const [orderStatusIndex] = await pool.query(
    `SELECT INDEX_NAME
     FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'employee_docs' AND INDEX_NAME = 'idx_employee_docs_order_status'
     LIMIT 1`,
    [DB_NAME]
  );
  if (!orderStatusIndex.length) {
    await pool.query("CREATE INDEX idx_employee_docs_order_status ON employee_docs (order_status)");
  }

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
      `INSERT INTO employee_docs (employee_id, awb_no, form_type, order_status, created_at, pdf_link, generated_by_type)
       SELECT d.employee_id, d.awb_no, d.form_type,
              CASE WHEN d.form_type = 'Manifest' THEN 'manifest' ELSE 'processing' END,
              d.created_at, d.pdf_link, 'employee'
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

function formatManifestNumber(sequenceNo) {
  return String(sequenceNo).padStart(4, "0");
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

async function allocateNextManifestNumber() {
  const [rows] = await pool.query(
    `SELECT manifest_number
     FROM employee_docs
     WHERE manifest_number IS NOT NULL AND manifest_number <> ''
     ORDER BY CAST(manifest_number AS UNSIGNED) DESC, id DESC
     LIMIT 1`
  );

  const lastManifestNumber = rows.length ? String(rows[0].manifest_number || "").trim() : "";
  const lastSequence = /^\d+$/.test(lastManifestNumber) ? Number(lastManifestNumber) : 0;
  const nextSequence = lastSequence + 1;

  return {
    manifestNumber: formatManifestNumber(nextSequence),
    sequenceNo: nextSequence,
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

    if (/invalid_grant/i.test(providerMessage)) {
      return res.status(500).json({
        ok: false,
        message:
          "Google OAuth refresh token invalid ya expired hai. GOOGLE_OAUTH_REFRESH_TOKEN dobara generate karein.",
      });
    }

    if (status === 401) {
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

function normalizeOrderStatus(input, fallback = "processing") {
  const raw = String(input || "").trim().toLowerCase();
  if (!raw) return fallback;

  if (raw === "processing") return "processing";
  if (raw === "manifest" || raw === "manifested") return "manifest";
  if (raw === "in_transit" || raw === "in transit") return "in_transit";
  if (raw === "out_for_delivery" || raw === "out for delivery") return "out_for_delivery";
  if (raw === "delivered") return "delivered";
  return fallback;
}

function readClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").trim();
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  return String(req.socket?.remoteAddress || "").trim();
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
    const dbErrorCodes = new Set([
      "ECONNREFUSED",
      "ETIMEDOUT",
      "ENOTFOUND",
      "ER_ACCESS_DENIED_ERROR",
      "ER_BAD_DB_ERROR",
      "PROTOCOL_CONNECTION_LOST",
    ]);
    if (dbErrorCodes.has(err?.code)) {
      return res.status(503).json({
        ok: false,
        message: "Database unavailable. Please contact admin.",
      });
    }
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

    if (!BREVO_API_KEY && !transporter) {
      return res.status(500).json({
        ok: false,
        message:
          "Email sending is not configured. Set BREVO_API_KEY and OTP_FROM_EMAIL, or configure SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS.",
      });
    }

    await sendOtpEmail({ to: cleanEmail, otp });

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

    if (err?.code === "BREVO_AUTH") {
      return res.status(500).json({
        ok: false,
        message: "Brevo auth failed. Check BREVO_API_KEY and verified sender email.",
      });
    }

    if (err?.code === "BREVO_SENDER_MISSING") {
      return res.status(500).json({
        ok: false,
        message: "Brevo sender email missing. Set OTP_FROM_EMAIL to your verified sender email.",
      });
    }

    if (err?.code === "BREVO_SEND") {
      return res.status(500).json({
        ok: false,
        message: err.providerMessage || "Brevo email send failed. Verify sender/domain in Brevo.",
      });
    }

    if (err?.code === "ESOCKET" || err?.code === "ETIMEDOUT") {
      return res.status(500).json({
        ok: false,
        message: IS_RENDER
          ? "SMTP connection failed. Render free service par SMTP ports (25/465/587) blocked ho sakte hain. Paid instance use karein ya email provider/API (Brevo/Resend/SendGrid) par switch karein."
          : "SMTP connection failed. Check SMTP_HOST/SMTP_PORT and internet connection.",
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
              d.generated_by_type, d.generated_by_company_id, d.generated_by_company_name,
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
              d.last_scan_latitude, d.last_scan_longitude, d.last_scan_ip, d.last_scan_at,
              d.generated_by_type,
              d.generated_by_company_id,
              d.generated_by_company_name,
              d.generated_by_admin_name,
              CASE
                WHEN d.generated_by_type = 'self' THEN CONCAT('Self (', COALESCE(d.generated_by_company_name, 'Company'), ')')
                WHEN d.generated_by_type = 'admin' THEN CONCAT('Generated by Admin (', COALESCE(d.generated_by_admin_name, ?), ')')
                ELSE e.name
              END AS generated_by_name,
              CASE
                WHEN d.generated_by_type = 'self' THEN CONCAT('Generated on ', DATE_FORMAT(d.created_at, '%Y-%m-%d %H:%i:%s'))
                WHEN d.generated_by_type = 'admin' THEN DATE_FORMAT(d.created_at, '%Y-%m-%d %H:%i:%s')
                ELSE e.employee_id
              END AS generated_by_employee_id
       FROM employee_docs d
       LEFT JOIN employee e ON e.id = d.employee_id
       WHERE d.form_type = 'Doct' AND DATE(d.created_at) = ?
       ORDER BY d.created_at DESC, d.id DESC`,
      [ADMIN_NAME, targetDate]
    );

    const docs = rows.map((row) => ({
      ...row,
      edit_url:
        String(row.generated_by_type || "").toLowerCase() === "self"
          ? `/doct?docId=${encodeURIComponent(row.id)}&companyId=${encodeURIComponent(
              row.generated_by_company_id || ""
            )}&admin=1`
          : String(row.generated_by_type || "").toLowerCase() === "admin"
            ? `/doct?docId=${encodeURIComponent(row.id)}&generatedBy=admin&admin=1`
          : `/doct?docId=${encodeURIComponent(row.id)}&employeeId=${encodeURIComponent(
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
    const companyIdInput = req.body?.companyId;
    const accountType = String(req.body?.accountType || "").trim().toLowerCase();

    if (!consignor) {
      return res.status(400).json({ ok: false, message: "consignor is required" });
    }

    let employeeDbId = null;
    const companyDbId = await resolveCompanyDbId(companyIdInput);
    const isAdminFlow = accountType === "admin";
    const isCompanySelfFlow = accountType === "company" || (!!companyDbId && !employeeIdInput);

    if (isCompanySelfFlow) {
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
      if (companyName && consignor.toLowerCase() !== companyName.toLowerCase()) {
        return res.status(400).json({
          ok: false,
          message: "Company account can generate DOCT only for its own consignor name",
        });
      }
    }

    if (!isAdminFlow && employeeIdInput !== undefined && employeeIdInput !== null && String(employeeIdInput).trim()) {
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

app.get("/api/manifests/next-number", async (_req, res) => {
  try {
    const allocated = await allocateNextManifestNumber();
    return res.json({
      ok: true,
      message: "Manifest number generated",
      manifest: allocated,
    });
  } catch (err) {
    console.error("Generate manifest number error:", err);
    return res.status(500).json({ ok: false, message: "Failed to generate manifest number" });
  }
});

app.post("/api/manifests", async (req, res) => {
  try {
    const docIds = Array.isArray(req.body?.docIds)
      ? req.body.docIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
      : [];
    const manifestNumber = String(req.body?.manifestNumber || "").trim();
    const toName = String(req.body?.toName || "").trim();
    const destination = String(req.body?.destination || "").trim();
    const manifestDate = String(req.body?.manifestDate || "").trim();
    const through = String(req.body?.through || "").trim();

    if (!docIds.length) {
      return res.status(400).json({ ok: false, message: "Select at least one order" });
    }

    if (!/^\d{4,}$/.test(manifestNumber)) {
      return res.status(400).json({ ok: false, message: "Manifest number must be numeric" });
    }

    if (!destination) {
      return res.status(400).json({ ok: false, message: "Destination is required" });
    }

    if (!manifestDate || Number.isNaN(Date.parse(manifestDate))) {
      return res.status(400).json({ ok: false, message: "Valid manifest date is required" });
    }

    const placeholders = docIds.map(() => "?").join(", ");
    const [rows] = await pool.query(
      `SELECT id
       FROM employee_docs
       WHERE id IN (${placeholders})
         AND order_status = 'processing'
         AND (manifest_number IS NULL OR manifest_number = '')`,
      docIds
    );

    if (rows.length !== docIds.length) {
      return res.status(400).json({
        ok: false,
        message: "Selected orders must exist in processing and should not already be part of a manifest",
      });
    }

    const [duplicate] = await pool.query(
      `SELECT id
       FROM employee_docs
       WHERE manifest_number = ?
       LIMIT 1`,
      [manifestNumber]
    );
    if (duplicate.length) {
      return res.status(409).json({ ok: false, message: "Manifest number already exists" });
    }

    await pool.query(
      `UPDATE employee_docs
       SET order_status = 'in_transit',
           manifest_number = ?,
           manifest_to_name = ?,
           manifest_destination = ?,
           manifest_date = ?,
           manifest_through = ?
       WHERE id IN (${placeholders})`,
      [manifestNumber, toName || null, destination, manifestDate, through || null, ...docIds]
    );

    return res.json({
      ok: true,
      message: "Manifest created successfully",
      manifest: {
        manifestNumber,
        toName,
        destination,
        manifestDate,
        through,
        docIds,
        orderStatus: "in_transit",
      },
    });
  } catch (err) {
    console.error("Create manifest error:", err);
    return res.status(500).json({ ok: false, message: "Failed to create manifest" });
  }
});

app.put("/api/manifests/:manifestNumber", async (req, res) => {
  try {
    const manifestNumber = String(req.params?.manifestNumber || "").trim();
    const toName = String(req.body?.toName || "").trim();
    const destination = String(req.body?.destination || "").trim();
    const manifestDate = String(req.body?.manifestDate || "").trim();
    const through = String(req.body?.through || "").trim();
    const keepDocIds = Array.isArray(req.body?.keepDocIds)
      ? req.body.keepDocIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
      : null;
    const addDocIds = Array.isArray(req.body?.addDocIds)
      ? req.body.addDocIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
      : [];

    if (!manifestNumber) {
      return res.status(400).json({ ok: false, message: "Manifest number is required" });
    }

    if (!destination) {
      return res.status(400).json({ ok: false, message: "Destination is required" });
    }

    if (!manifestDate || Number.isNaN(Date.parse(manifestDate))) {
      return res.status(400).json({ ok: false, message: "Valid manifest date is required" });
    }

    const [existingRows] = await pool.query(
      `SELECT id
       FROM employee_docs
       WHERE manifest_number = ?`,
      [manifestNumber]
    );

    if (!existingRows.length) {
      return res.status(404).json({ ok: false, message: "Manifest not found" });
    }

    if (keepDocIds && !keepDocIds.length) {
      return res.status(400).json({ ok: false, message: "Manifest must keep at least one order" });
    }

    if (keepDocIds) {
      const existingIds = existingRows.map((row) => Number(row.id));
      const invalidIds = keepDocIds.filter((id) => !existingIds.includes(id));
      if (invalidIds.length) {
        return res.status(400).json({ ok: false, message: "Some selected orders do not belong to this manifest" });
      }

      const placeholders = keepDocIds.map(() => "?").join(", ");
      await pool.query(
        `UPDATE employee_docs
         SET manifest_number = NULL,
             manifest_to_name = NULL,
             manifest_destination = NULL,
             manifest_date = NULL,
             manifest_through = NULL,
             order_status = 'processing'
         WHERE manifest_number = ?
           AND id NOT IN (${placeholders})`,
        [manifestNumber, ...keepDocIds]
      );
    }

    if (addDocIds.length) {
      const addPlaceholders = addDocIds.map(() => "?").join(", ");
      const [addRows] = await pool.query(
        `SELECT id
         FROM employee_docs
         WHERE id IN (${addPlaceholders})
           AND order_status = 'processing'
           AND (manifest_number IS NULL OR manifest_number = '')`,
        addDocIds
      );

      if (addRows.length !== addDocIds.length) {
        return res.status(400).json({
          ok: false,
          message: "Added orders must be in processing and should not already belong to another manifest",
        });
      }

      await pool.query(
        `UPDATE employee_docs
         SET manifest_number = ?,
             manifest_to_name = ?,
             manifest_destination = ?,
             manifest_date = ?,
             manifest_through = ?,
             order_status = 'in_transit'
         WHERE id IN (${addPlaceholders})`,
        [manifestNumber, toName || null, destination, manifestDate, through || null, ...addDocIds]
      );
    }

    const [result] = await pool.query(
      `UPDATE employee_docs
       SET manifest_to_name = ?,
           manifest_destination = ?,
           manifest_date = ?,
           manifest_through = ?,
           order_status = 'in_transit'
       WHERE manifest_number = ?`,
      [toName || null, destination, manifestDate, through || null, manifestNumber]
    );

    if (!result?.affectedRows) {
      return res.status(404).json({ ok: false, message: "Manifest not found" });
    }

    return res.json({
      ok: true,
      message: "Manifest updated successfully",
      manifest: {
        manifestNumber,
        toName,
        destination,
        manifestDate,
        through,
      },
    });
  } catch (err) {
    console.error("Update manifest error:", err);
    return res.status(500).json({ ok: false, message: "Failed to update manifest" });
  }
});

app.delete("/api/manifests/:manifestNumber", async (req, res) => {
  try {
    const manifestNumber = String(req.params?.manifestNumber || "").trim();
    if (!manifestNumber) {
      return res.status(400).json({ ok: false, message: "Manifest number is required" });
    }

    const [result] = await pool.query(
      `UPDATE employee_docs
       SET manifest_number = NULL,
           manifest_to_name = NULL,
           manifest_destination = NULL,
           manifest_date = NULL,
           manifest_through = NULL,
           order_status = 'processing'
       WHERE manifest_number = ?`,
      [manifestNumber]
    );

    if (!result?.affectedRows) {
      return res.status(404).json({ ok: false, message: "Manifest not found" });
    }

    return res.json({ ok: true, message: "Manifest deleted successfully", manifestNumber });
  } catch (err) {
    console.error("Delete manifest error:", err);
    return res.status(500).json({ ok: false, message: "Failed to delete manifest" });
  }
});

app.post("/api/docs", async (req, res) => {
  try {
    const employeeIdInput = req.body?.employeeId;
    const companyIdInput = req.body?.companyId;
    const accountType = String(req.body?.accountType || "").trim().toLowerCase();
    const employeeDbId = await resolveEmployeeDbId(employeeIdInput);
    const companyDbId = await resolveCompanyDbId(companyIdInput);
    const docId = Number(req.body?.docId || 0);
    const awbNo = String(req.body?.awbNo || "").trim();
    const formType = req.body?.formType === "Manifest" ? "Manifest" : "Doct";
    const inferredDefaultStatus = formType === "Manifest" ? "manifest" : "processing";
    const orderStatus = normalizeOrderStatus(req.body?.orderStatus, inferredDefaultStatus);
    const pdfLink = req.body?.pdfLink ? String(req.body.pdfLink) : null;
    const rawFormData =
      req.body?.formData && typeof req.body.formData === "object" ? req.body.formData : null;
    const consignorName = String(rawFormData?.form?.consignor || "").trim() || null;
    const formData = rawFormData ? JSON.stringify(rawFormData) : null;
    const isAdminFlow = accountType === "admin";
    const isCompanySelfFlow = accountType === "company" || (!!companyDbId && !employeeDbId);

    let generatedByType = "employee";
    let generatedByCompanyId = null;
    let generatedByCompanyName = null;
    let generatedByAdminName = null;

    if (isAdminFlow) {
      generatedByType = "admin";
      generatedByAdminName = ADMIN_NAME;
    } else if (isCompanySelfFlow) {
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
      generatedByType = "self";
      generatedByCompanyId = companyDbId;
      generatedByCompanyName = String(companyRows[0].company_name || "").trim() || null;

      if (
        consignorName &&
        generatedByCompanyName &&
        consignorName.toLowerCase() !== generatedByCompanyName.toLowerCase()
      ) {
        return res.status(400).json({
          ok: false,
          message: "Company account can generate DOCT only for its own consignor name",
        });
      }
    } else if (!employeeDbId) {
      return res.status(400).json({ ok: false, message: "Invalid employee id" });
    }

    if (!awbNo) {
      return res.status(400).json({ ok: false, message: "awbNo is required" });
    }

    if (docId > 0) {
      let updateResult;
      if (generatedByType === "self") {
        [updateResult] = await pool.query(
          `UPDATE employee_docs
           SET employee_id = NULL, generated_by_type = 'self', generated_by_company_id = ?,
               generated_by_company_name = ?, generated_by_admin_name = NULL,
               awb_no = ?, form_type = ?, order_status = ?, pdf_link = ?, form_data = ?
           WHERE id = ? AND generated_by_type = 'self' AND generated_by_company_id = ?`,
          [
            generatedByCompanyId,
            generatedByCompanyName,
            awbNo,
            formType,
            orderStatus,
            pdfLink,
            formData,
            docId,
            generatedByCompanyId,
          ]
        );
      } else if (generatedByType === "admin") {
        [updateResult] = await pool.query(
          `UPDATE employee_docs
           SET employee_id = NULL, generated_by_type = 'admin', generated_by_company_id = NULL,
               generated_by_company_name = NULL, generated_by_admin_name = ?, awb_no = ?, form_type = ?,
               order_status = ?, pdf_link = ?, form_data = ?
           WHERE id = ? AND generated_by_type = 'admin'`,
          [generatedByAdminName, awbNo, formType, orderStatus, pdfLink, formData, docId]
        );
      } else {
        [updateResult] = await pool.query(
          `UPDATE employee_docs
           SET employee_id = ?, generated_by_type = 'employee', generated_by_company_id = NULL,
               generated_by_company_name = NULL, generated_by_admin_name = NULL,
               awb_no = ?, form_type = ?, order_status = ?, pdf_link = ?, form_data = ?
           WHERE id = ? AND employee_id = ?`,
          [employeeDbId, awbNo, formType, orderStatus, pdfLink, formData, docId, employeeDbId]
        );
      }

      if (!updateResult?.affectedRows) {
        return res.status(404).json({ ok: false, message: "Document not found" });
      }

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
          generated_by_type: generatedByType,
          generated_by_company_id: generatedByCompanyId,
          generated_by_company_name: generatedByCompanyName,
          generated_by_admin_name: generatedByAdminName,
          awb_no: awbNo,
          form_type: formType,
          order_status: orderStatus,
          pdf_link: pdfLink,
        },
      });
    }

    const [result] = await pool.query(
      `INSERT INTO employee_docs (
         employee_id, generated_by_type, generated_by_company_id, generated_by_company_name,
         generated_by_admin_name, awb_no, form_type, order_status, pdf_link, form_data
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        generatedByType === "employee" ? employeeDbId : null,
        generatedByType,
        generatedByCompanyId,
        generatedByCompanyName,
        generatedByAdminName,
        awbNo,
        formType,
        orderStatus,
        pdfLink,
        formData,
      ]
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
        generated_by_type: generatedByType,
        generated_by_company_id: generatedByCompanyId,
        generated_by_company_name: generatedByCompanyName,
        generated_by_admin_name: generatedByAdminName,
        awb_no: awbNo,
        form_type: formType,
        order_status: orderStatus,
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
              d.generated_by_type,
              d.generated_by_company_id,
              d.generated_by_company_name,
              d.generated_by_admin_name,
              e.name AS generated_by_name,
              e.employee_id AS generated_by_employee_id,
              ab.consignor_name,
              CASE
                WHEN d.generated_by_type = 'self' THEN CONCAT(
                  'Self (',
                  COALESCE(d.generated_by_company_name, 'Company'),
                  ' | ',
                  DATE_FORMAT(d.created_at, '%Y-%m-%d %H:%i:%s'),
                  ')'
                )
                WHEN d.generated_by_type = 'admin' THEN CONCAT(
                  'Generated by Admin (',
                  COALESCE(d.generated_by_admin_name, ?),
                  ' | ',
                  DATE_FORMAT(d.created_at, '%Y-%m-%d %H:%i:%s'),
                  ')'
                )
                ELSE NULL
              END AS generated_by_detail
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
      [ADMIN_NAME, companyName]
    );

    return res.json({ ok: true, docs: rows });
  } catch (err) {
    console.error("Fetch company docs error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch company documents" });
  }
});

app.get("/api/orders", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT d.id, d.employee_id, d.awb_no, d.form_type, d.order_status, d.created_at, d.pdf_link, d.form_data,
              d.manifest_number, d.manifest_to_name, d.manifest_destination, d.manifest_date, d.manifest_through,
              d.last_scan_latitude, d.last_scan_longitude, d.last_scan_ip, d.last_scan_at,
              d.generated_by_type, d.generated_by_company_id, d.generated_by_company_name, d.generated_by_admin_name,
              e.name AS generated_by_name,
              e.employee_id AS generated_by_employee_id,
              ab.consignor_name
       FROM employee_docs d
       LEFT JOIN employee e ON e.id = d.employee_id
       LEFT JOIN airwaybills ab ON ab.awb_number = d.awb_no
       ORDER BY d.created_at DESC, d.id DESC`
    );

    const docs = rows.map((row) => {
      let parsedFormData = null;
      if (row.form_data) {
        try {
          parsedFormData = JSON.parse(row.form_data);
        } catch {
          parsedFormData = null;
        }
      }

      const form = parsedFormData?.form && typeof parsedFormData.form === "object" ? parsedFormData.form : {};
      const status = normalizeOrderStatus(
        row.order_status,
        row.form_type === "Manifest" ? "manifest" : "processing"
      );
      const boxCount = String(form.noOfBox || "").trim();
      const totalWeight = String(form.totalWeight || "").trim();
      const weightSummary = [boxCount ? `${boxCount} Box` : "", totalWeight ? `${totalWeight} Kg` : ""]
        .filter(Boolean)
        .join(" • ");

      return {
        id: row.id,
        awb_no: row.awb_no,
        form_type: row.form_type,
        order_status: status,
        created_at: row.created_at,
        pdf_link: row.pdf_link,
        customer_name: String(form.consignee || "").trim() || "N/A",
        customer_phone: String(form.mobileNumber || "").trim() || "",
        consignor_name: String(form.consignor || row.consignor_name || "").trim() || "N/A",
        origin: String(form.origin || "").trim(),
        destination: String(form.destination || "").trim(),
        payment_label: "Prepaid",
        service_type: "B2C",
        order_reference: row.awb_no ? `#${row.awb_no}` : `#${row.id}`,
        order_category: String(form.contentDescription || "").trim() || "General",
        box_count: boxCount || "N/A",
        total_weight: totalWeight || "N/A",
        weight_summary: weightSummary || "N/A",
        manifest_number: row.manifest_number || "",
        manifest_to_name: row.manifest_to_name || "",
        manifest_destination: row.manifest_destination || "",
        manifest_date: row.manifest_date || null,
        manifest_through: row.manifest_through || "",
        last_scan_latitude: row.last_scan_latitude,
        last_scan_longitude: row.last_scan_longitude,
        last_scan_ip: row.last_scan_ip || "",
        last_scan_at: row.last_scan_at,
        generated_by_type: row.generated_by_type,
        generated_by_name:
          row.generated_by_type === "admin"
            ? row.generated_by_admin_name || ADMIN_NAME
            : row.generated_by_name || row.generated_by_company_name || "Self",
        generated_by_employee_id: row.generated_by_employee_id || "",
        generated_by_company_name: row.generated_by_company_name || "",
        generated_by_admin_name: row.generated_by_admin_name || "",
      };
    });

    return res.json({ ok: true, docs });
  } catch (err) {
    console.error("Fetch orders error:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch processing orders" });
  }
});

app.post("/api/orders/mark-in-transit", async (req, res) => {
  try {
    const docId = Number(req.body?.docId || 0);
    const awbNo = String(req.body?.awbNo || "").trim();
    const normalizedAwb = awbNo.replace(/\s+/g, "").toUpperCase();

    if (!docId || !awbNo) {
      return res.status(400).json({ ok: false, message: "docId and awbNo are required" });
    }

    const [result] = await pool.query(
      `UPDATE employee_docs
       SET order_status = 'in_transit'
       WHERE id = ? AND REPLACE(UPPER(TRIM(awb_no)), ' ', '') = ?`,
      [docId, normalizedAwb]
    );

    if (!result?.affectedRows) {
      return res.status(404).json({ ok: false, message: "Order not found" });
    }

    return res.json({
      ok: true,
      message: "Order moved to in transit",
      order: {
        id: docId,
        awb_no: awbNo,
        order_status: "in_transit",
      },
    });
  } catch (err) {
    console.error("Mark in transit error:", err);
    return res.status(500).json({ ok: false, message: "Failed to move order to in transit" });
  }
});

app.post("/api/orders/scan", async (req, res) => {
  try {
    const docId = Number(req.body?.docId || 0);
    const awbNo = String(req.body?.awbNo || "").trim();
    const manifestNumber = String(req.body?.manifestNumber || "").trim();
    const normalizedAwb = awbNo.replace(/\s+/g, "").toUpperCase();
    const latitudeRaw = req.body?.latitude;
    const longitudeRaw = req.body?.longitude;
    const latitude =
      latitudeRaw === undefined || latitudeRaw === null || latitudeRaw === ""
        ? null
        : Number(latitudeRaw);
    const longitude =
      longitudeRaw === undefined || longitudeRaw === null || longitudeRaw === ""
        ? null
        : Number(longitudeRaw);

    if (!awbNo && !manifestNumber) {
      return res.status(400).json({ ok: false, message: "awbNo or manifestNumber is required" });
    }

    if ((latitude !== null && Number.isNaN(latitude)) || (longitude !== null && Number.isNaN(longitude))) {
      return res.status(400).json({ ok: false, message: "Invalid latitude or longitude" });
    }

    const clientIp = readClientIp(req);
    if (manifestNumber) {
      const [manifestRows] = await pool.query(
        `SELECT id
         FROM employee_docs
         WHERE manifest_number = ?`,
        [manifestNumber]
      );

      if (!manifestRows.length) {
        return res.status(404).json({ ok: false, message: "Manifest not found" });
      }

      await pool.query(
        `UPDATE employee_docs
         SET order_status = 'in_transit',
             last_scan_latitude = ?,
             last_scan_longitude = ?,
             last_scan_ip = ?,
             last_scan_at = CURRENT_TIMESTAMP
         WHERE manifest_number = ?`,
        [latitude, longitude, clientIp || null, manifestNumber]
      );

      return res.json({
        ok: true,
        message: "Manifest orders updated",
        manifest: {
          manifestNumber,
          totalOrders: manifestRows.length,
          order_status: "in_transit",
          last_scan_latitude: latitude,
          last_scan_longitude: longitude,
          last_scan_ip: clientIp || "",
        },
      });
    }

    let rows = [];
    if (docId) {
      const [rowsByIdAndAwb] = await pool.query(
        `SELECT id, awb_no, manifest_number, order_status
         FROM employee_docs
         WHERE id = ? AND REPLACE(UPPER(TRIM(awb_no)), ' ', '') = ?
         LIMIT 1`,
        [docId, normalizedAwb]
      );
      rows = rowsByIdAndAwb;
    }

    if (!rows.length) {
      const [rowsByAwb] = await pool.query(
        `SELECT id, awb_no, manifest_number, order_status
         FROM employee_docs
         WHERE REPLACE(UPPER(TRIM(awb_no)), ' ', '') = ?
         ORDER BY id DESC
         LIMIT 1`,
        [normalizedAwb]
      );
      rows = rowsByAwb;
    }

    if (!rows.length) {
      return res.status(404).json({ ok: false, message: "Order not found" });
    }

    const matchedDoc = rows[0];
    const hasManifest = String(matchedDoc.manifest_number || "").trim();
    const currentStatus = String(matchedDoc.order_status || "").trim().toLowerCase();
    if (!hasManifest && !["in_transit", "out_for_delivery", "delivered"].includes(currentStatus)) {
      return res.status(400).json({
        ok: false,
        message: "Is order ka manifest abhi create nahi hua hai",
      });
    }

    const matchedDocId = Number(matchedDoc.id);
    await pool.query(
      `UPDATE employee_docs
       SET order_status = 'in_transit',
           last_scan_latitude = ?,
           last_scan_longitude = ?,
           last_scan_ip = ?,
           last_scan_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [latitude, longitude, clientIp || null, matchedDocId]
    );

    return res.json({
      ok: true,
      message: "Order moved to in transit",
      order: {
        id: matchedDocId,
        awb_no: awbNo,
        order_status: "in_transit",
        last_scan_latitude: latitude,
        last_scan_longitude: longitude,
        last_scan_ip: clientIp || "",
      },
    });
  } catch (err) {
    console.error("Order scan update error:", err);
    return res.status(500).json({ ok: false, message: "Failed to update scanned order" });
  }
});

app.get("/api/docs/:id", async (req, res) => {
  try {
    const employeeDbId = await resolveEmployeeDbId(req.query?.employeeId);
    const companyDbId = await resolveCompanyDbId(req.query?.companyId);
    const isAdminDoc = String(req.query?.accountType || req.query?.generatedBy || "").trim().toLowerCase() === "admin";
    const docId = Number(req.params?.id || 0);
    if (!docId) {
      return res.status(400).json({ ok: false, message: "Invalid doc id" });
    }
    if (!employeeDbId && !companyDbId && !isAdminDoc) {
      return res.status(400).json({ ok: false, message: "Invalid employee/company/admin id" });
    }

    let rows;
    if (employeeDbId) {
      [rows] = await pool.query(
        `SELECT id, employee_id, generated_by_type, generated_by_company_id, generated_by_company_name, generated_by_admin_name,
                awb_no, form_type, created_at, pdf_link, form_data
         FROM employee_docs
         WHERE id = ? AND employee_id = ?
         LIMIT 1`,
        [docId, employeeDbId]
      );
    } else if (isAdminDoc) {
      [rows] = await pool.query(
        `SELECT id, employee_id, generated_by_type, generated_by_company_id, generated_by_company_name, generated_by_admin_name,
                awb_no, form_type, created_at, pdf_link, form_data
         FROM employee_docs
         WHERE id = ? AND generated_by_type = 'admin'
         LIMIT 1`,
        [docId]
      );
    } else {
      [rows] = await pool.query(
        `SELECT id, employee_id, generated_by_type, generated_by_company_id, generated_by_company_name, generated_by_admin_name,
                awb_no, form_type, created_at, pdf_link, form_data
         FROM employee_docs
         WHERE id = ? AND generated_by_type = 'self' AND generated_by_company_id = ?
         LIMIT 1`,
        [docId, companyDbId]
      );
    }

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
