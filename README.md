# Enterprise SQL Server Security Implementation 🛡️

## 📌 Project Overview
This project demonstrates the implementation of advanced database security features in Microsoft SQL Server to protect Personally Identifiable Information (PII) and ensure compliance with data protection regulations (such as GDPR). The simulated environment involves a financial database (`SecureBankDB`) where sensitive customer data must be shielded from unauthorized access, even from internal employees.

## 🛠️ Technologies & Features Used
- **Database Engine:** SQL Server (T-SQL)
- **Dynamic Data Masking (DDM):** Obfuscating sensitive data (emails, phone numbers, credit cards) at the presentation layer.
- **Row-Level Security (RLS):** Restricting data row access dynamically based on user context and region.
- **Data Discovery & Classification:** Tagging sensitive columns for compliance tracking.
- **SQL Server Auditing:** Tracking and logging database events to the file system for forensic analysis.
- **Security Architecture:** Schema isolation and Principle of Least Privilege (RBAC).

## 💼 Business Scenario
A financial institution requires its database to be secured such that:
1. Customer Service Agents can only view customer data from their specific assigned region (e.g., Casablanca).
2. Even when viewing authorized data, highly sensitive information like Credit Cards and Emails must be partially or fully masked.
3. Every attempt to query (`SELECT`) or modify (`UPDATE`) the sensitive tables must be logged to a secure file for weekly security audits.

---

## 🚀 Implementation Script

```sql
-- ======================================================================
-- Enterprise Database Security Master Script
-- Author: [Your Name]
-- ======================================================================

USE master;
GO
IF DB_ID('SecureBankDB') IS NOT NULL DROP DATABASE SecureBankDB;
GO
CREATE DATABASE SecureBankDB;
GO
USE SecureBankDB;
GO

-- 1. Schema Isolation
CREATE SCHEMA SecureData;
GO

-- 2. Table Creation with Dynamic Data Masking (DDM)
CREATE TABLE SecureData.Customers (
    CustomerID INT IDENTITY(1,1) PRIMARY KEY,
    FullName NVARCHAR(100) NOT NULL,
    -- Mask Email (e.g., aXXX@XXXX.com)
    Email NVARCHAR(100) MASKED WITH (FUNCTION = 'email()') NOT NULL,
    -- Mask Phone (e.g., 06XXX-XXX78)
    Phone NVARCHAR(20) MASKED WITH (FUNCTION = 'partial(2, "XXX-XXX", 2)') NOT NULL,
    -- Mask Credit Card completely
    CreditCard NVARCHAR(20) MASKED WITH (FUNCTION = 'default()') NOT NULL,
    Salary DECIMAL(18, 2),
    Region NVARCHAR(50)
);
GO

INSERT INTO SecureData.Customers (FullName, Email, Phone, CreditCard, Salary, Region)
VALUES 
('Ahmed Alami', 'ahmed.alami@email.com', '0612345678', '4532-1234-5678-9012', 15000, 'Casablanca'),
('Fatima Zahra', 'fatima.z@email.com', '0698765432', '4532-9876-5432-1098', 12000, 'Rabat');
GO

-- 3. Data Classification for GDPR Compliance
ADD SENSITIVITY CLASSIFICATION TO SecureData.Customers.Email
    WITH (LABEL = 'Confidential', INFORMATION_TYPE = 'Contact Info');
ADD SENSITIVITY CLASSIFICATION TO SecureData.Customers.CreditCard
    WITH (LABEL = 'Highly Confidential', INFORMATION_TYPE = 'Financial');
GO

-- 4. Role-Based Access Control (Least Privilege)
CREATE ROLE DataReadersRole;
GRANT SELECT ON SCHEMA::SecureData TO DataReadersRole;
GO
CREATE USER AppUser WITHOUT LOGIN;
ALTER ROLE DataReadersRole ADD MEMBER AppUser;
GO

-- 5. Row-Level Security (RLS) implementation
CREATE FUNCTION SecureData.fn_securitypredicate(@Region AS NVARCHAR(50))
    RETURNS TABLE
WITH SCHEMABINDING
AS
    -- Admin sees everything, AppUser only sees 'Casablanca'
    RETURN SELECT 1 AS fn_securitypredicate_result
    WHERE USER_NAME() = 'dbo' OR (USER_NAME() = 'AppUser' AND @Region = 'Casablanca');
GO

CREATE SECURITY POLICY RegionFilterPolicy
ADD FILTER PREDICATE SecureData.fn_securitypredicate(Region)
ON SecureData.Customers
WITH (STATE = ON);
GO

-- 6. Server & Database Auditing
USE master;
GO
CREATE SERVER AUDIT [SecureBank_Audit]
TO FILE (FILEPATH = 'C:\SQL_Audits\')
WITH (ON_FAILURE = CONTINUE);
GO
ALTER SERVER AUDIT [SecureBank_Audit] WITH (STATE = ON);
GO

USE SecureBankDB;
GO
CREATE DATABASE AUDIT SPECIFICATION [SecureBank_DB_Audit_Spec]
FOR SERVER AUDIT [SecureBank_Audit]
ADD (SELECT, UPDATE ON SecureData.Customers BY [public])
WITH (STATE = ON);
GO
```

## 📈 Results & Verification
To verify the security measures, we execute a query as the restricted `AppUser`:

```sql
EXECUTE AS USER = 'AppUser';
SELECT * FROM SecureData.Customers;
REVERT;
```
**Expected Outcome:** 
1. Only the "Casablanca" record is returned (RLS is active).
2. The `Email`, `Phone`, and `CreditCard` columns are masked (DDM is active).
3. The query execution is logged in the `C:\SQL_Audits\` folder for DBA review (Auditing is active).
