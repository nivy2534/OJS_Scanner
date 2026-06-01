import requests

def send_telegram(message):
    # Ganti dengan Token dari BotFather
    bot_token = "8791856318:AAGm_ToVA3uziBa8FUSIDufLA3IC8KwjtIc"
    # Ganti dengan ID dari bot Get ID
    chat_id = "1438751725"     
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message
    }
    
    try:
        requests.post(url, json=payload)
        print("[+] Pesan Telegram berhasil dikirim!")
    except Exception as e:
        print(f"[-] Gagal mengirim Telegram: {e}")

# Baris untuk ngetes kodenya jalan atau nggak
if __name__ == "__main__":
    send_telegram("Halo ! Mesin G2_Engine siap meluncur!")