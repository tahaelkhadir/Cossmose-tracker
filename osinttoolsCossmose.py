from flask import Flask, request, render_template
import instaloader
import whois
import requests
from bs4 import BeautifulSoup
import os
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

app = Flask(__name__)

def get_profile_info(username):
    inst = instaloader.Instaloader()
    profile = instaloader.Profile.from_username(inst.context, username)
    follower_count = profile.followers
    following_count = profile.followees
    email = "Email : Non disponible"
    phone_number = "Numéro de téléphone : Non disponible"
    profile_pic_url = profile.profile_pic_url

    posts = profile.get_posts()
    photo_data = []

    for post in posts:
        if not post.is_video:
            photo_url = post.url
            likes_count = post.likes
            location = post.location.name if post.location else "Localisation : Non disponible"
            date_posted = post.date.strftime("%Y-%m-%d %H:%M:%S")
            tags = ', '.join(post.caption_hashtags) if post.caption_hashtags else "Tags : Non disponible"
            photo_data.append((photo_url, likes_count, location, date_posted, tags))
    
    profile_info = {
        'username': profile.username,
        'full_name': profile.full_name,
        'followers': follower_count,
        'following': following_count,
        'email': email,
        'phone_number': phone_number,
        'profile_pic_url': profile_pic_url,
        'photos': photo_data
    }

    return profile_info


def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            'domain_name': domain_info.domain_name,
            'registrar': domain_info.registrar,
            'whois_server': domain_info.whois_server,
            'creation_date': domain_info.creation_date,
            'expiration_date': domain_info.expiration_date,
            'updated_date': domain_info.updated_date,
            'status': domain_info.status,
            'name_servers': domain_info.name_servers,
            'emails': domain_info.emails,
            'registrant_name': domain_info.name,
            'registrant_organization': domain_info.org,
            'registrant_street': domain_info.address,
            'registrant_city': domain_info.city,
            'registrant_state': domain_info.state,
            'registrant_postal_code': domain_info.zipcode,
            'registrant_country': domain_info.country,
            'registrant_phone': domain_info.phone
        }
    except Exception as e:
        return {'error': str(e)}



def google_dorks_advanced(query):
    search_query = query.split()
    dorks_command = ''
    for word in search_query:
        if word.startswith('intitle:') or word.startswith('inurl:') or word.startswith('filetype:'):
            dorks_command += f' {word}'
        else:
            dorks_command += f' "{word}"'
    url = f"https://www.google.com/search?q={dorks_command}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        return [{'title': 'Error', 'link': 'Unable to fetch results from Google'}]
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    results = []
    for g in soup.find_all('div', class_='tF2Cxc'):
        title_element = g.find('h3')
        if title_element:
            title = title_element.get_text()
            link = g.find('a')['href']
            results.append({'title': title, 'link': link})
    
    return results



def analyze_image(image_path):
    image = Image.open(image_path)
    exif_data = {}
    
    if image._getexif() is not None:
        for tag, value in image._getexif().items():
            tag_name = TAGS.get(tag, tag)
            if tag_name == "GPSInfo":
                gps_info = {}
                for key, val in value.items():
                    sub_tag_name = GPSTAGS.get(key, key)
                    gps_info[sub_tag_name] = val
                exif_data["GPSInfo"] = gps_info
            else:
                exif_data[tag_name] = value
    return exif_data


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        profile_info = get_profile_info(username)
        return render_template('profile.html', profile=profile_info)
    return render_template('index.html')

@app.route('/whois', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        domain = request.form['domain']
        whois_info = get_whois_info(domain)
        return render_template('whois.html', whois=whois_info)
    return render_template('index2.html')



@app.route('/dorks', methods=['GET', 'POST'])
def google_dorks_search():
    if request.method == 'POST':
        query = request.form['query']
        dorks_results = google_dorks_advanced(query)
        return render_template('dorks.html', dorks=dorks_results)
    return render_template('index3.html')


@app.route('/image', methods=['GET', 'POST'])
def image_analysis():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('image.html', error='Aucune image sélectionnée')
        file = request.files['file']
        if file.filename == '':
            return render_template('image.html', error='Aucune image sélectionnée')
        
        if not os.path.exists('CosImage'):
            os.makedirs('CosImage')

        image_path = os.path.join('CosImage', file.filename)
        file.save(image_path)
        exif_data = analyze_image(image_path)
        return render_template('imageExf.html', exif_data=exif_data)
    return render_template('image.html')

if __name__ == '__main__':
    app.run(debug=True)
