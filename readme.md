# 📜 **Smart Contract Auditor**  

🚀 **Smart Contract Auditor** is a powerful tool designed to **analyze Solidity smart contracts** for vulnerabilities using **Slither** and provide AI-powered insights via **LangChain**. With an easy-to-use interface built with **Tailwind CSS & DaisyUI**, this tool helps developers detect security issues in their contracts before they can be exploited.  

---

## ❗ **Why is this Important?**  

Every year, **millions of dollars** are stolen from crypto wallets due to security vulnerabilities in smart contracts. Issues like **reentrancy attacks, integer overflows, and access control flaws** have led to devastating hacks.  

### 🔥 **Some Notorious Hacks Due to Vulnerabilities**  
- **The DAO Hack (2016) - $60M+ stolen** due to a reentrancy vulnerability.  
- **Poly Network Hack (2021) - $600M stolen** due to improper access control.  
- **Nomad Bridge Hack (2022) - $190M lost** due to a simple initialization bug.  

💡 **To prevent such attacks**, I created this Smart Contract Auditor, allowing developers to scan their Solidity contracts **before deploying them on the blockchain**.  

---

## 🛠 **Tech Stack**  

This project is built using:  

| **Technology** | **Usage** |
|--------------|------------|
| **Django** | Backend framework |
| **Slither** | Smart contract static analysis |
| **LangChain** | AI-powered chatbot for explaining vulnerabilities |
| **SQLite** | User authentication database |
| **Tailwind CSS & DaisyUI** | Frontend design for a clean and modern UI |

---

## ⚡ **Features**  

✅ **Upload Solidity Smart Contracts** – Instantly scan for vulnerabilities.  
✅ **Automated Security Analysis** – Uses Slither to detect issues.  
✅ **AI-Powered Chatbot** – Ask AI about vulnerabilities and get instant explanations.  
✅ **User Authentication** – Secure login and access with SQLite.  
✅ **Modern UI** – Built with Tailwind & DaisyUI for a smooth experience.  

---

 
## 🎯 **How it Works**  

1. **Upload a Solidity smart contract (.sol file).**  
2. **Slither scans the contract** for vulnerabilities like:  
   - Reentrancy  
   - Integer Overflow/Underflow  
   - Unchecked External Calls  
   - Uninitialized Storage Variables  
3. **The AI Chatbot (LangChain) explains the vulnerabilities** and suggests fixes.  
4. **Secure your smart contract before deploying it!**  

## 🚀 **How to Use**  

### 1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/yourusername/smart-contract-auditor.git
cd smart-contract-auditor