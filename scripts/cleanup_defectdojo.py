import requests
import os

# Konfigurasi dari Environment Variables
DD_URL = os.getenv('DEFECTDOJO_URL')
DD_API_KEY = os.getenv('DEFECTDOJO_API_KEY')
PRODUCT_ID = os.getenv('DEFECTDOJO_PRODUCT_ID')

headers = {
    'Authorization': f'Token {DD_API_KEY}',
    'Content-Type': 'application/json'
}

def archive_old_engagements(keep_limit=5):
    # 1. Ambil daftar engagement untuk produk terkait
    url = f"{DD_URL}/api/v2/engagements/?product={PRODUCT_ID}&ordering=-created"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        engagements = response.json().get('results', [])
        
        # 2. Identifikasi engagement di luar batas limit (Engagement lama)
        to_archive = engagements[keep_limit:]
        
        for eng in to_archive:
            eng_id = eng['id']
            # 3. Update status menjadi Archived (status penutupan)
            patch_url = f"{DD_URL}/api/v2/engagements/{eng_id}/"
            # Mengubah status aktif menjadi false
            patch_data = {"active": False, "status": "Completed"}
            requests.patch(patch_url, headers=headers, json=patch_data)
            print(f"Archived Engagement ID: {eng_id} - {eng['name']}")

if __name__ == "__main__":
    archive_old_engagements()