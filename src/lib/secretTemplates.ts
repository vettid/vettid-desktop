// Secret templates — ported from Android SecretsModels.kt. One template
// per common "thing the user wants to store" (credit card, login, etc.).
// Saving a template fires one `secret.add` per non-blank field with a
// shared alias so the catalog groups them as one card.

export type FieldHint =
    | 'TEXT'
    | 'PASSWORD'
    | 'NUMBER'
    | 'DATE'
    | 'EXPIRY_DATE'
    | 'COUNTRY'
    | 'STATE'
    | 'PIN'
    | 'EMAIL'
    | 'PHONE'
    | 'URL'
    | 'NOTE';

export interface TemplateField {
    name: string;
    hint: FieldHint;
}

export interface SecretTemplate {
    id: string;
    name: string;
    category: string;
    icon: string;
    description: string;
    fields: TemplateField[];
    /** Some templates ask for a "group name" alongside the alias —
     *  e.g. crypto wallets want "Wallet Name". Optional. */
    groupNamePrompt?: string;
}

export const SECRET_TEMPLATES: SecretTemplate[] = [
    {
        id: 'login',
        name: 'Login Credential',
        category: 'LOGIN',
        icon: '🔐',
        description: 'Website or service login with username, password, and 2FA.',
        fields: [
            { name: 'Website/Service', hint: 'URL' },
            { name: 'Username', hint: 'TEXT' },
            { name: 'Password', hint: 'PASSWORD' },
            { name: '2FA Method', hint: 'TEXT' },
            { name: 'Recovery Codes', hint: 'NOTE' },
        ],
    },
    {
        id: 'credit-card',
        name: 'Credit Card',
        category: 'CREDIT_CARD',
        icon: '💳',
        description: 'Card number, expiration, CVV, and cardholder name.',
        fields: [
            { name: 'Cardholder Name', hint: 'TEXT' },
            { name: 'Card Number', hint: 'NUMBER' },
            { name: 'Expiration', hint: 'EXPIRY_DATE' },
            { name: 'CVV', hint: 'PIN' },
            { name: 'Card Issuer', hint: 'TEXT' },
        ],
    },
    {
        id: 'debit-card',
        name: 'Debit Card',
        category: 'CREDIT_CARD',
        icon: '💳',
        description: 'Debit card details with PIN.',
        fields: [
            { name: 'Cardholder Name', hint: 'TEXT' },
            { name: 'Card Number', hint: 'NUMBER' },
            { name: 'Expiration', hint: 'EXPIRY_DATE' },
            { name: 'PIN', hint: 'PIN' },
            { name: 'Bank Name', hint: 'TEXT' },
        ],
    },
    {
        id: 'bank-account',
        name: 'Bank Account',
        category: 'BANK_ACCOUNT',
        icon: '🏦',
        description: 'Bank, account number, routing number.',
        fields: [
            { name: 'Bank Name', hint: 'TEXT' },
            { name: 'Account Number', hint: 'NUMBER' },
            { name: 'Routing Number', hint: 'NUMBER' },
            { name: 'Account Type', hint: 'TEXT' },
        ],
    },
    {
        id: 'crypto-wallet',
        name: 'Cryptocurrency Wallet',
        category: 'CRYPTOCURRENCY',
        icon: '₿',
        description: 'Public address and seed phrase.',
        groupNamePrompt: 'Wallet Name',
        fields: [
            { name: 'Public Address', hint: 'TEXT' },
            { name: 'Seed Phrase', hint: 'PASSWORD' },
        ],
    },
    {
        id: 'drivers-license',
        name: "Driver's License",
        category: 'DRIVERS_LICENSE',
        icon: '🪪',
        description: "Driver's license number and expiration.",
        fields: [
            { name: 'License Number', hint: 'TEXT' },
            { name: 'State/Province', hint: 'STATE' },
            { name: 'Expiration', hint: 'DATE' },
            { name: 'Date of Birth', hint: 'DATE' },
            { name: 'License Class', hint: 'TEXT' },
        ],
    },
    {
        id: 'passport',
        name: 'Passport',
        category: 'PASSPORT',
        icon: '🛂',
        description: 'Passport number, country, and expiration.',
        fields: [
            { name: 'Passport Number', hint: 'TEXT' },
            { name: 'Country', hint: 'COUNTRY' },
            { name: 'Expiration', hint: 'DATE' },
            { name: 'Date of Birth', hint: 'DATE' },
            { name: 'Place of Birth', hint: 'TEXT' },
        ],
    },
    {
        id: 'insurance',
        name: 'Insurance',
        category: 'INSURANCE',
        icon: '🛡️',
        description: 'Insurance policy details.',
        fields: [
            { name: 'Provider', hint: 'TEXT' },
            { name: 'Policy Number', hint: 'TEXT' },
            { name: 'Group Number', hint: 'TEXT' },
            { name: 'Member ID', hint: 'TEXT' },
        ],
    },
    {
        id: 'ssn',
        name: 'Social Security Number',
        category: 'SSN',
        icon: '🆔',
        description: 'Single-field SSN entry.',
        fields: [
            { name: 'Social Security Number', hint: 'PASSWORD' },
        ],
    },
    {
        id: 'wifi',
        name: 'WiFi Network',
        category: 'WIFI',
        icon: '📶',
        description: 'Network name and password.',
        fields: [
            { name: 'Network Name (SSID)', hint: 'TEXT' },
            { name: 'Password', hint: 'PASSWORD' },
        ],
    },
    {
        id: 'software-license',
        name: 'Software License',
        category: 'SOFTWARE_LICENSE',
        icon: '💿',
        description: 'License key and product details.',
        fields: [
            { name: 'Product Name', hint: 'TEXT' },
            { name: 'License Key', hint: 'PASSWORD' },
            { name: 'Registered Email', hint: 'EMAIL' },
            { name: 'Expiry Date', hint: 'DATE' },
            { name: 'Seats/Devices', hint: 'NUMBER' },
        ],
    },
    {
        id: 'ssh-key',
        name: 'SSH Key',
        category: 'SSH',
        icon: '🗝️',
        description: 'SSH key pair with passphrase.',
        fields: [
            { name: 'Label', hint: 'TEXT' },
            { name: 'Public Key', hint: 'NOTE' },
            { name: 'Private Key', hint: 'PASSWORD' },
            { name: 'Passphrase', hint: 'PASSWORD' },
            { name: 'Associated Host', hint: 'TEXT' },
        ],
    },
    {
        id: 'pgp-key',
        name: 'PGP/GPG Key',
        category: 'CERTIFICATE',
        icon: '🗝️',
        description: 'PGP keypair with fingerprint.',
        fields: [
            { name: 'Email', hint: 'EMAIL' },
            { name: 'Key ID', hint: 'TEXT' },
            { name: 'Fingerprint', hint: 'TEXT' },
            { name: 'Public Key', hint: 'NOTE' },
            { name: 'Private Key', hint: 'PASSWORD' },
            { name: 'Passphrase', hint: 'PASSWORD' },
        ],
    },
    {
        id: 'vpn',
        name: 'VPN Configuration',
        category: 'VPN',
        icon: '🌐',
        description: 'VPN provider and credentials.',
        fields: [
            { name: 'Provider', hint: 'TEXT' },
            { name: 'Server Address', hint: 'TEXT' },
            { name: 'Username', hint: 'TEXT' },
            { name: 'Password/Key', hint: 'PASSWORD' },
            { name: 'Protocol', hint: 'TEXT' },
        ],
    },
    {
        id: 'totp',
        name: 'TOTP Secret',
        category: 'TOTP',
        icon: '⏱️',
        description: 'TOTP shared secret for 2FA setup.',
        fields: [
            { name: 'Service Name', hint: 'TEXT' },
            { name: 'Account/Email', hint: 'EMAIL' },
            { name: 'Secret Key', hint: 'PASSWORD' },
            { name: 'Algorithm', hint: 'TEXT' },
            { name: 'Digits', hint: 'NUMBER' },
        ],
    },
    {
        id: 'api-credential',
        name: 'API Credential',
        category: 'API_KEY',
        icon: '🔑',
        description: 'API key/secret pair.',
        fields: [
            { name: 'Service Name', hint: 'TEXT' },
            { name: 'API Key', hint: 'PASSWORD' },
            { name: 'API Secret', hint: 'PASSWORD' },
            { name: 'Base URL', hint: 'URL' },
            { name: 'Rate Limit Notes', hint: 'NOTE' },
        ],
    },
    {
        id: 'prescription',
        name: 'Medical Prescription',
        category: 'OTHER',
        icon: '💊',
        description: 'Medication, dosage, and prescriber.',
        fields: [
            { name: 'Medication Name', hint: 'TEXT' },
            { name: 'Dosage', hint: 'TEXT' },
            { name: 'Frequency', hint: 'TEXT' },
            { name: 'Prescribing Doctor', hint: 'TEXT' },
            { name: 'Pharmacy', hint: 'TEXT' },
            { name: 'RX Number', hint: 'TEXT' },
        ],
    },
    {
        id: 'vehicle-registration',
        name: 'Vehicle Registration',
        category: 'VEHICLE',
        icon: '🚗',
        description: 'License plate and VIN.',
        fields: [
            { name: 'Plate Number', hint: 'TEXT' },
            { name: 'State', hint: 'STATE' },
            { name: 'VIN', hint: 'TEXT' },
            { name: 'Registration Number', hint: 'TEXT' },
            { name: 'Expiry Date', hint: 'DATE' },
        ],
    },
    {
        id: 'loyalty-card',
        name: 'Loyalty/Rewards Card',
        category: 'LOYALTY',
        icon: '🎟️',
        description: 'Member number and tier.',
        fields: [
            { name: 'Program Name', hint: 'TEXT' },
            { name: 'Member Number', hint: 'TEXT' },
            { name: 'Tier/Status', hint: 'TEXT' },
            { name: 'PIN', hint: 'PIN' },
        ],
    },
    {
        id: 'tax-filing',
        name: 'Tax Filing Reference',
        category: 'TAX',
        icon: '🧾',
        description: 'Tax return details for a year.',
        fields: [
            { name: 'Tax Year', hint: 'NUMBER' },
            { name: 'Filing Status', hint: 'TEXT' },
            { name: 'AGI', hint: 'NUMBER' },
            { name: 'Refund/Owed', hint: 'TEXT' },
            { name: 'Preparer', hint: 'TEXT' },
            { name: 'Confirmation Number', hint: 'TEXT' },
        ],
    },
    {
        id: 'digital-certificate',
        name: 'Digital Certificate',
        category: 'CERTIFICATE',
        icon: '📜',
        description: 'X.509 / TLS certificate details.',
        fields: [
            { name: 'Subject/Common Name', hint: 'TEXT' },
            { name: 'Issuer', hint: 'TEXT' },
            { name: 'Serial Number', hint: 'TEXT' },
            { name: 'Valid From', hint: 'DATE' },
            { name: 'Valid To', hint: 'DATE' },
            { name: 'PEM Content', hint: 'NOTE' },
        ],
    },
];
