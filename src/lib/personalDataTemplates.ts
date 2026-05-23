// Personal-data multi-field templates — ported from Android
// PersonalDataModels.kt. Each template defines a set of fields with
// fixed dotted namespaces; saving fires one personal-data.update with
// {fields, aliases} where every field gets the same alias.

import type { FieldHint } from './secretTemplates';

export interface DataTemplateField {
    name: string;
    namespace: string;
    hint: FieldHint;
}

export interface DataTemplate {
    id: string;
    name: string;
    category: string;
    icon: string;
    description: string;
    fields: DataTemplateField[];
}

export const DATA_TEMPLATES: DataTemplate[] = [
    {
        id: 'home-address',
        name: 'Home Address',
        category: 'address',
        icon: '🏠',
        description: 'Street, city, state, postal code, country.',
        fields: [
            { name: 'Street', namespace: 'address.home.street', hint: 'TEXT' },
            { name: 'Street Line 2', namespace: 'address.home.street_2', hint: 'TEXT' },
            { name: 'City', namespace: 'address.home.city', hint: 'TEXT' },
            { name: 'State/Province', namespace: 'address.home.state', hint: 'STATE' },
            { name: 'Postal Code', namespace: 'address.home.postal_code', hint: 'TEXT' },
            { name: 'Country', namespace: 'address.home.country', hint: 'COUNTRY' },
        ],
    },
    {
        id: 'business-address',
        name: 'Business Address',
        category: 'address',
        icon: '🏢',
        description: 'Work / business address with company.',
        fields: [
            { name: 'Company', namespace: 'address.work.company', hint: 'TEXT' },
            { name: 'Street', namespace: 'address.work.street', hint: 'TEXT' },
            { name: 'Street Line 2', namespace: 'address.work.street_2', hint: 'TEXT' },
            { name: 'City', namespace: 'address.work.city', hint: 'TEXT' },
            { name: 'State/Province', namespace: 'address.work.state', hint: 'STATE' },
            { name: 'Postal Code', namespace: 'address.work.postal_code', hint: 'TEXT' },
            { name: 'Country', namespace: 'address.work.country', hint: 'COUNTRY' },
        ],
    },
    {
        id: 'family-member',
        name: 'Family Member',
        category: 'family',
        icon: '👪',
        description: 'Family member contact info.',
        fields: [
            { name: 'Full Name', namespace: 'contact.family.name', hint: 'TEXT' },
            { name: 'Relationship', namespace: 'contact.family.relationship', hint: 'TEXT' },
            { name: 'Phone', namespace: 'contact.family.phone', hint: 'PHONE' },
            { name: 'Email', namespace: 'contact.family.email', hint: 'EMAIL' },
        ],
    },
    {
        id: 'emergency-contact',
        name: 'Emergency Contact',
        category: 'contact',
        icon: '🚨',
        description: 'Person to reach in emergency.',
        fields: [
            { name: 'Name', namespace: 'contact.emergency.name', hint: 'TEXT' },
            { name: 'Relationship', namespace: 'contact.emergency.relationship', hint: 'TEXT' },
            { name: 'Phone', namespace: 'contact.emergency.phone', hint: 'PHONE' },
        ],
    },
    {
        id: 'full-name',
        name: 'Full Name',
        category: 'identity',
        icon: '🧑',
        description: 'Prefix, names, suffix.',
        fields: [
            { name: 'Prefix', namespace: 'identity.name.prefix', hint: 'TEXT' },
            { name: 'First Name', namespace: 'identity.name.first', hint: 'TEXT' },
            { name: 'Middle Name', namespace: 'identity.name.middle', hint: 'TEXT' },
            { name: 'Last Name', namespace: 'identity.name.last', hint: 'TEXT' },
            { name: 'Suffix', namespace: 'identity.name.suffix', hint: 'TEXT' },
        ],
    },
    {
        id: 'government-id',
        name: 'Government ID',
        category: 'identity',
        icon: '🪪',
        description: 'Government-issued ID with expiry.',
        fields: [
            { name: 'ID Type', namespace: 'identity.gov_id.type', hint: 'TEXT' },
            { name: 'Number', namespace: 'identity.gov_id.number', hint: 'TEXT' },
            { name: 'Issuing Authority', namespace: 'identity.gov_id.authority', hint: 'TEXT' },
            { name: 'Expiry Date', namespace: 'identity.gov_id.expiry', hint: 'DATE' },
        ],
    },
    {
        id: 'dependent',
        name: 'Dependent',
        category: 'family',
        icon: '🧒',
        description: 'A dependent (child, etc.).',
        fields: [
            { name: 'Full Name', namespace: 'family.dependent.name', hint: 'TEXT' },
            { name: 'Relationship', namespace: 'family.dependent.relationship', hint: 'TEXT' },
            { name: 'Date of Birth', namespace: 'family.dependent.dob', hint: 'DATE' },
            { name: 'SSN (last 4)', namespace: 'family.dependent.ssn_last4', hint: 'NUMBER' },
            { name: 'School', namespace: 'family.dependent.school', hint: 'TEXT' },
            { name: 'Medical Insurance ID', namespace: 'family.dependent.insurance_id', hint: 'TEXT' },
        ],
    },
    {
        id: 'social-media',
        name: 'Social Media Profile',
        category: 'digital',
        icon: '📱',
        description: 'Profile on a social platform.',
        fields: [
            { name: 'Platform', namespace: 'digital.social.platform', hint: 'TEXT' },
            { name: 'Username/Handle', namespace: 'digital.social.handle', hint: 'TEXT' },
            { name: 'Profile URL', namespace: 'digital.social.url', hint: 'URL' },
            { name: 'Associated Email', namespace: 'digital.social.email', hint: 'EMAIL' },
        ],
    },
    {
        id: 'employment',
        name: 'Employment Record',
        category: 'professional',
        icon: '💼',
        description: 'Job history entry.',
        fields: [
            { name: 'Company', namespace: 'professional.job.company', hint: 'TEXT' },
            { name: 'Job Title', namespace: 'professional.job.title', hint: 'TEXT' },
            { name: 'Department', namespace: 'professional.job.department', hint: 'TEXT' },
            { name: 'Start Date', namespace: 'professional.job.start_date', hint: 'DATE' },
            { name: 'End Date', namespace: 'professional.job.end_date', hint: 'DATE' },
            { name: 'Work Phone', namespace: 'professional.job.phone', hint: 'PHONE' },
            { name: 'Work Email', namespace: 'professional.job.email', hint: 'EMAIL' },
        ],
    },
    {
        id: 'professional-license',
        name: 'Professional License',
        category: 'professional',
        icon: '📋',
        description: 'A professional license/credential.',
        fields: [
            { name: 'License Type', namespace: 'professional.license.type', hint: 'TEXT' },
            { name: 'License Number', namespace: 'professional.license.number', hint: 'TEXT' },
            { name: 'Issuing Authority', namespace: 'professional.license.authority', hint: 'TEXT' },
            { name: 'Issue Date', namespace: 'professional.license.issue_date', hint: 'DATE' },
            { name: 'Expiry Date', namespace: 'professional.license.expiry', hint: 'DATE' },
            { name: 'State/Province', namespace: 'professional.license.state', hint: 'STATE' },
        ],
    },
    {
        id: 'degree',
        name: 'Degree',
        category: 'education',
        icon: '🎓',
        description: 'An academic degree.',
        fields: [
            { name: 'Institution Name', namespace: 'education.degree.school', hint: 'TEXT' },
            { name: 'Degree Type', namespace: 'education.degree.type', hint: 'TEXT' },
            { name: 'Major', namespace: 'education.degree.major', hint: 'TEXT' },
            { name: 'Minor', namespace: 'education.degree.minor', hint: 'TEXT' },
            { name: 'Graduation Date', namespace: 'education.degree.graduated', hint: 'DATE' },
            { name: 'Student ID', namespace: 'education.degree.student_id', hint: 'TEXT' },
            { name: 'GPA', namespace: 'education.degree.gpa', hint: 'TEXT' },
        ],
    },
    {
        id: 'vehicle-record',
        name: 'Vehicle Record',
        category: 'vehicle',
        icon: '🚙',
        description: 'A vehicle you own.',
        fields: [
            { name: 'Year', namespace: 'vehicle.record.year', hint: 'NUMBER' },
            { name: 'Make', namespace: 'vehicle.record.make', hint: 'TEXT' },
            { name: 'Model', namespace: 'vehicle.record.model', hint: 'TEXT' },
            { name: 'Color', namespace: 'vehicle.record.color', hint: 'TEXT' },
            { name: 'VIN', namespace: 'vehicle.record.vin', hint: 'TEXT' },
            { name: 'License Plate', namespace: 'vehicle.record.plate', hint: 'TEXT' },
            { name: 'State', namespace: 'vehicle.record.state', hint: 'STATE' },
            { name: 'Registration Expiry', namespace: 'vehicle.record.expiry', hint: 'DATE' },
        ],
    },
    {
        id: 'visa',
        name: 'Visa',
        category: 'travel',
        icon: '🛂',
        description: 'Travel visa details.',
        fields: [
            { name: 'Country', namespace: 'travel.visa.country', hint: 'COUNTRY' },
            { name: 'Visa Type', namespace: 'travel.visa.type', hint: 'TEXT' },
            { name: 'Visa Number', namespace: 'travel.visa.number', hint: 'TEXT' },
            { name: 'Issue Date', namespace: 'travel.visa.issue', hint: 'DATE' },
            { name: 'Expiry Date', namespace: 'travel.visa.expiry', hint: 'DATE' },
            { name: 'Entries', namespace: 'travel.visa.entries', hint: 'TEXT' },
        ],
    },
    {
        id: 'loyalty-program',
        name: 'Loyalty Program',
        category: 'membership',
        icon: '🏷️',
        description: 'Membership in a rewards program.',
        fields: [
            { name: 'Program Name', namespace: 'membership.loyalty.program', hint: 'TEXT' },
            { name: 'Provider', namespace: 'membership.loyalty.provider', hint: 'TEXT' },
            { name: 'Member Number', namespace: 'membership.loyalty.number', hint: 'TEXT' },
            { name: 'Tier/Status', namespace: 'membership.loyalty.tier', hint: 'TEXT' },
            { name: 'Expiry Date', namespace: 'membership.loyalty.expiry', hint: 'DATE' },
        ],
    },
    {
        id: 'beneficiary',
        name: 'Beneficiary',
        category: 'legal',
        icon: '⚖️',
        description: 'Beneficiary on accounts/insurance.',
        fields: [
            { name: 'Full Name', namespace: 'legal.beneficiary.name', hint: 'TEXT' },
            { name: 'Relationship', namespace: 'legal.beneficiary.relationship', hint: 'TEXT' },
            { name: 'Date of Birth', namespace: 'legal.beneficiary.dob', hint: 'DATE' },
            { name: 'Phone', namespace: 'legal.beneficiary.phone', hint: 'PHONE' },
            { name: 'Email', namespace: 'legal.beneficiary.email', hint: 'EMAIL' },
            { name: 'Percentage/Share', namespace: 'legal.beneficiary.share', hint: 'TEXT' },
        ],
    },
    {
        id: 'prescription',
        name: 'Prescription',
        category: 'medical',
        icon: '💊',
        description: 'Active prescription.',
        fields: [
            { name: 'Medication Name', namespace: 'medical.prescription.name', hint: 'TEXT' },
            { name: 'Dosage', namespace: 'medical.prescription.dosage', hint: 'TEXT' },
            { name: 'Frequency', namespace: 'medical.prescription.frequency', hint: 'TEXT' },
            { name: 'Prescribing Doctor', namespace: 'medical.prescription.doctor', hint: 'TEXT' },
            { name: 'Pharmacy', namespace: 'medical.prescription.pharmacy', hint: 'TEXT' },
            { name: 'Refills Remaining', namespace: 'medical.prescription.refills', hint: 'NUMBER' },
            { name: 'Expiry Date', namespace: 'medical.prescription.expiry', hint: 'DATE' },
        ],
    },
    {
        id: 'insurance-policy',
        name: 'Insurance Policy',
        category: 'medical',
        icon: '🛡️',
        description: 'Health/medical insurance policy.',
        fields: [
            { name: 'Provider', namespace: 'medical.insurance.provider', hint: 'TEXT' },
            { name: 'Plan Name', namespace: 'medical.insurance.plan', hint: 'TEXT' },
            { name: 'Policy Number', namespace: 'medical.insurance.policy', hint: 'TEXT' },
            { name: 'Group Number', namespace: 'medical.insurance.group', hint: 'TEXT' },
            { name: 'Member ID', namespace: 'medical.insurance.member_id', hint: 'TEXT' },
            { name: 'Subscriber Name', namespace: 'medical.insurance.subscriber', hint: 'TEXT' },
            { name: 'Effective Date', namespace: 'medical.insurance.effective', hint: 'DATE' },
            { name: 'Copay Amount', namespace: 'medical.insurance.copay', hint: 'TEXT' },
        ],
    },
    {
        id: 'org-membership',
        name: 'Organization Membership',
        category: 'membership',
        icon: '🏛️',
        description: 'Membership in an organization.',
        fields: [
            { name: 'Organization Name', namespace: 'membership.org.name', hint: 'TEXT' },
            { name: 'Membership Type/Tier', namespace: 'membership.org.tier', hint: 'TEXT' },
            { name: 'Member ID', namespace: 'membership.org.id', hint: 'TEXT' },
            { name: 'Join Date', namespace: 'membership.org.join_date', hint: 'DATE' },
            { name: 'Expiry Date', namespace: 'membership.org.expiry', hint: 'DATE' },
            { name: 'Contact Phone', namespace: 'membership.org.phone', hint: 'PHONE' },
        ],
    },
    {
        id: 'property-record',
        name: 'Property Record',
        category: 'property',
        icon: '🏘️',
        description: 'Real estate property record.',
        fields: [
            { name: 'Property Address', namespace: 'property.record.address', hint: 'TEXT' },
            { name: 'Property Type', namespace: 'property.record.type', hint: 'TEXT' },
            { name: 'Purchase Date', namespace: 'property.record.purchased', hint: 'DATE' },
            { name: 'Mortgage Lender', namespace: 'property.record.lender', hint: 'TEXT' },
            { name: 'Mortgage Account', namespace: 'property.record.mortgage_account', hint: 'TEXT' },
            { name: 'HOA Name', namespace: 'property.record.hoa', hint: 'TEXT' },
            { name: 'HOA Account', namespace: 'property.record.hoa_account', hint: 'TEXT' },
        ],
    },
];
