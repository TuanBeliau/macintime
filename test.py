import validators

website = "detik.com"

if not validators.url(f'https://{website}'):
    print('hai')