# **WebTester: A Web Server Testing Tool**

## **1. Overview**

The `WebTester` tool is designed to:

1. Check if a web server supports HTTP/2.
2. Retrieve and list cookies, including their name, expiry time, and domain (if any).
3. Determine if a webpage is password-protected.

This tool is implemented in Python and uses socket programming to interact with web servers.

---

## **2. Deliverables**

The submission must include:

- `WebTester.py`: The Python script containing the implementation of the tool.
- `readme.txt`: This file, explaining how to run and use the tool.
- A single `.zip` file containing the script and this `readme.txt`.

---

## **3. How to Run**

### **Prerequisites**

- Ensure Python 3 is installed.
- Run the tool on the `linux.csc.uvic.ca` server to ensure compatibility.

### **Execution**

1. Log in to the server using SSH.
2. Upload the `WebTester.py` script to your workspace.
3. Execute the tool using:

```python
   
   python3 WebTester.py <URL>
```

   Replace `<URL>` with the target web server's URL (e.g., `www.example.com`).

---

## **4. Input and Output**

### **Input**

- The tool accepts a single Uniform Resource Identifier (URI) as input.

### **Output**

The tool outputs:

1. Whether the web server supports HTTP/2 (e.g., "Supports http2: no").
2. A list of cookies (e.g., name, domain, expiry time).
3. Whether the web page is password-protected (e.g., "Password-protected: no").

#### **Example**

Input:

```python

python3 WebTester.py https://github.com/danigallegdup/WebTester
```

Output:
  
```python

website: www.example.com
1. Supports http2: yes
2. List of Cookies:
   cookie name: SESSIONID, domain name: www.example.com
   cookie name: PREF, expires time: Wed, 20-Dec-2023 00:00:00 GMT; domain name: .example.com
3. Password-protected: no
```

---

## **5. Marking Scheme**

The tool will be graded as follows:

- **Error Handling**: 10%
- **Correct Output for HTTP/2 Support**: 20%
- **Handling HTTP Redirects (302/301)**: 20%
- **List of Cookies**: 30%
- **Correct Output for Password Protection**: 15%
- **ReadMe File**: 5%

---

## **6. Notes**

- Ensure the code handles HTTP redirects (status codes 301 and 302) by sending follow-up requests to the new URI provided in the `Location` header.
- Output must include detailed information on cookies, including their name, domain, and expiry time (if available).
- Password protection is identified by analyzing HTTP responses for status codes or login forms.

---

## **7. Testing Environment**

The tool must be tested on the `linux.csc.uvic.ca` server to ensure compatibility. Use `python3` and ensure all dependencies are supported by the server.
