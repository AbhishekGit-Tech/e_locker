from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import secrets
from Crypto.Cipher import AES
from django.utils import timezone
from django.http import HttpResponse, HttpResponseForbidden
from .models import EncryptedFile, UserProfile



def landing(request):
    # Prevent a freshly-created superuser from auto-landing:
    if request.user.is_authenticated:
        if request.user.is_superuser:
            logout(request)
            return render(request, 'core/landing.html')
        return redirect('home')
    return render(request, 'core/landing.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        step = request.POST.get('step')

        # STEP 1: Registration form
        if step == 'form':
            u = request.POST['username'].strip()
            e = request.POST['email'].strip()
            p = request.POST['password']
            c = request.POST['confirm_password']

            if p != c:
                messages.error(request, "Passwords don’t match.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(username=u).exists():
                messages.error(request, "Username taken.")
                return render(request,'core/register.html',{'step':'form'})
            if User.objects.filter(email=e).exists():
                messages.error(request, "Email already used.")
                return render(request,'core/register.html',{'step':'form'})

            otp = f"{secrets.randbelow(900000)+100000:06d}"
            request.session['reg_username'] = u
            request.session['reg_email']    = e
            request.session['reg_password'] = p
            request.session['reg_otp']      = otp

            send_mail(
                subject="e-Locker Registration OTP",
                message=f"Your registration code is {otp}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[e],
                fail_silently=False,
            )
            return render(request, 'core/register.html', {'step': 'otp'})

        # STEP 2: OTP verification
        if step == 'otp':
            entered = request.POST.get('otp_input','').strip()
            real    = request.session.get('reg_otp')
            if entered == real:
                user = User.objects.create_user(
                    username=request.session['reg_username'],
                    email=   request.session['reg_email'],
                    password=request.session['reg_password']
                )
                user.save()
                # clean up reg data only
                for k in ('reg_username','reg_email','reg_password','reg_otp'):
                    request.session.pop(k, None)
                messages.success(request, "Registered! Now log in below.")
                return redirect('login_simple')

            messages.error(request, "Invalid OTP.")
            return render(request, 'core/register.html', {'step': 'otp'})

    # GET or fallback
    return render(request, 'core/register.html', {'step': 'form'})


def resolve_user(identifier):
    """Return User object matching username or email, or None."""
    if "@" in identifier:
        return User.objects.filter(email__iexact=identifier).first()
    else:
        return User.objects.filter(username__iexact=identifier).first()


def login_simple_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        ident = request.POST['identifier'].strip().lower()
        pwd   = request.POST['password']

        # 1) Resolve identifier → User object
        if "@" in ident:
            user_obj = User.objects.filter(email__iexact=ident).first()
        else:
            user_obj = User.objects.filter(username__iexact=ident).first()

        if not user_obj:
            messages.error(request, "No account with that username/email.")
            return render(request, 'core/login_simple.html')

        # 2) Authenticate credentials
        user = authenticate(request, username=user_obj.username, password=pwd)
        if user:
            # 3) Before login: fetch old key from profile
            profile    = user.userprofile
            old_key_hex = profile.last_key

            # 4) Generate brand-new session key
            new_key_hex = secrets.token_hex(32)

            # 5) Re-encrypt all files using old → new
            reencrypt_all_files(user, old_key_hex, new_key_hex)

            # 6) Log the user in & store the new key
            login(request, user)
            request.session['enc_key']        = new_key_hex
            profile.last_key = new_key_hex
            profile.save()

            return redirect('home')

        messages.error(request, "Invalid credentials.")
    return render(request, 'core/login_simple.html')



def login_otp_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        step = request.POST.get('step')

        # STEP 1: user enters identifier → send OTP
        if step == 'form':
            ident = request.POST['identifier'].strip().lower()
            if "@" in ident:
                user_obj = User.objects.filter(email__iexact=ident).first()
            else:
                user_obj = User.objects.filter(username__iexact=ident).first()

            if not user_obj:
                messages.error(request, "No account with that username/email.")
                return render(request, 'core/login.html', {'step': 'form'})

            # Generate & store OTP in session, send to user’s email
            otp = f"{secrets.randbelow(9000)+1000:04d}"
            request.session['login_identifier'] = ident
            request.session['login_otp']        = otp

            send_mail(
                subject="e-Locker Login OTP",
                message=f"Your login code is {otp}",
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user_obj.email],
                fail_silently=False,
            )
            return render(request, 'core/login.html', {'step': 'verify'})

        # STEP 2: user enters password+OTP concatenated
        if step == 'verify':
            combo = request.POST.get('password','')
            real_otp = request.session.get('login_otp')
            ident    = request.session.get('login_identifier')

            entered_otp = combo[-4:] if len(combo) > 4 else ''
            entered_pw  = combo[:-4]

            # Resolve the same identifier again
            if "@" in ident:
                user_obj = User.objects.filter(email__iexact=ident).first()
            else:
                user_obj = User.objects.filter(username__iexact=ident).first()

            # Verify OTP first
            if entered_otp == real_otp and user_obj:
                # Attempt password authentication
                user = authenticate(request, username=user_obj.username, password=entered_pw)
                if user:
                    # 1) Old key from profile
                    profile     = user.userprofile
                    old_key_hex = profile.last_key

                    # 2) Generate new key
                    new_key_hex = secrets.token_hex(32)

                    # 3) Re-encrypt all files
                    reencrypt_all_files(user, old_key_hex, new_key_hex)

                    # 4) Finalize login & store new key
                    login(request, user)
                    request.session['enc_key']        = new_key_hex
                    profile.last_key = new_key_hex
                    profile.save()

                    # Clean up OTP‐related session entries
                    request.session.pop('login_identifier', None)
                    request.session.pop('login_otp', None)

                    return redirect('home')

            messages.error(request, "Invalid password+OTP combination.")
            return render(request, 'core/login.html', {'step': 'verify'})

    # Default: show “enter email/username” form
    return render(request, 'core/login.html', {'step': 'form'})


@login_required
def home(request):
    # 1) Get or generate the per-session encryption key   
    if request.user.is_superuser:
        return redirect('/admin/')

    key = request.session.get('enc_key')
    if not key:
        # 32 bytes = 256 bits, hex-encoded to 64 chars
        key = secrets.token_hex(32)
        request.session['enc_key'] = key

    # 2) Render home.html, including the key in context
    return render(request, 'core/home.html', {
        'username': request.user.username,
        'email':    request.user.email,
        'enc_key':  key,
    })


def logout_view(request):
    logout(request)
    return redirect('landing')


@login_required
def upload_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        # 1) Grab the session key and decode hex → bytes
        key_hex = request.session['enc_key']
        key = bytes.fromhex(key_hex)

        # 2) Read the uploaded file bytes
        f = request.FILES['file']
        data = f.read()

        # 3) AES-GCM encrypt
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce

        # 4) Save to DB
        EncryptedFile.objects.create(
            owner=request.user,
            name=f.name,
            nonce=nonce,
            tag=tag,
            ciphertext=ciphertext
        )
        messages.success(request, f"Encrypted & saved {f.name}")
        return redirect('home')

    return redirect('home')


@login_required
def open_anyway(request, file_id):
    """
    Display the raw ciphertext in hex form (gibberish) for the given file.
    """
    # 1) Fetch the EncryptedFile, ensure owner matches
    try:
        ef = EncryptedFile.objects.get(pk=file_id, owner=request.user)
    except EncryptedFile.DoesNotExist:
        return HttpResponseForbidden("You do not own this file.")

    # 2) Convert the binary ciphertext to hex for display
    hex_cipher = ef.ciphertext.hex()

    # 3) Return a simple HTML page with the hex inside a <pre> block
    return HttpResponse(
        "<h1>Encrypted content of “{}”</h1>"
        "<pre style='white-space: pre-wrap; word-wrap: break-word;'>"
        "{}"
        "</pre>".format(ef.name, hex_cipher)
    )


def reencrypt_all_files(user, old_key_hex, new_key_hex):
    """
    Decrypt each EncryptedFile of `user` using old_key_hex,
    then re-encrypt with new_key_hex, updating nonce/tag/ciphertext.
    """
    # If old_key_hex is empty, skip (first-ever login / no existing files)
    if not old_key_hex:
        return

    old_key = bytes.fromhex(old_key_hex)
    new_key = bytes.fromhex(new_key_hex)

    for ef in EncryptedFile.objects.filter(owner=user):
        # 1) Decrypt with old key
        cipher_old = AES.new(old_key, AES.MODE_GCM, nonce=ef.nonce)
        try:
            plaintext = cipher_old.decrypt_and_verify(ef.ciphertext, ef.tag)
        except Exception:
            # If decryption fails, skip re-encrypt; file may be corrupt or key mismatch
            continue

        # 2) Encrypt with new key
        cipher_new = AES.new(new_key, AES.MODE_GCM)
        ciphertext, tag = cipher_new.encrypt_and_digest(plaintext)
        nonce = cipher_new.nonce

        # 3) Update the database record
        ef.nonce      = nonce
        ef.tag        = tag
        ef.ciphertext = ciphertext
        ef.save()

@login_required
def decrypt_view(request, file_id):
    """
    Step A (GET): generate & email a 4-digit OTP, then show a form
                  asking for “SessionKey + OTP.”
    Step B (POST): verify SessionKey+OTP, decrypt, and display plaintext.
    """
    # 1) Fetch the EncryptedFile and confirm ownership
    try:
        ef = EncryptedFile.objects.get(pk=file_id, owner=request.user)
    except EncryptedFile.DoesNotExist:
        return HttpResponseForbidden("You do not own this file.")

    # 2) If GET → generate OTP, email it, render form
    if request.method == 'GET':
        otp = f"{secrets.randbelow(9000) + 1000:04d}"
        request.session['decrypt_file_id'] = file_id
        request.session['decrypt_otp']     = otp

        send_mail(
            subject="e-Locker Decryption OTP",
            message=f"Your decryption code for \"{ef.name}\" is: {otp}",
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[request.user.email],
            fail_silently=False,
        )
        return render(request, 'core/decrypt.html', {
            'file_name': ef.name,
        })

    # 3) If POST → verify combo and decrypt
    combo       = request.POST.get('combo','').strip()
    real_otp    = request.session.get('decrypt_otp')
    session_key = request.session.get('enc_key')
    stored_id   = request.session.get('decrypt_file_id')

    # 3a) Check file_id matches session
    if stored_id is None or stored_id != file_id:
        return HttpResponseForbidden("Invalid decryption attempt.")

    if not session_key or not real_otp:
        return HttpResponse("Session expired or no OTP found.", status=400)

    entered_otp = combo[-4:] if len(combo) > 4 else ''
    entered_key = combo[:-4]

    # 3b) Verify OTP & key
    if entered_otp != real_otp or entered_key != session_key:
        return render(request, 'core/decrypt.html', {
            'file_name': ef.name,
            'error': "Invalid key+OTP combination.",
        })

    # 3c) Decrypt with AES-GCM
    key_bytes = bytes.fromhex(session_key)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=ef.nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ef.ciphertext, ef.tag)
    except Exception:
        return HttpResponse("Decryption failed (wrong key or corrupted).", status=400)

    # 3d) Clean up OTP from session
    request.session.pop('decrypt_otp', None)
    request.session.pop('decrypt_file_id', None)

    # 3e) Show plaintext
    text = plaintext.decode('utf-8', errors='replace')
    return render(request, 'core/decrypt.html', {
        'file_name': ef.name,
        'plaintext': text,
    })


@login_required
def delete_file(request, file_id):
    """
    Allow the owner to delete their EncryptedFile record.
    """
    try:
        ef = EncryptedFile.objects.get(pk=file_id, owner=request.user)
    except EncryptedFile.DoesNotExist:
        return HttpResponseForbidden("You do not own this file.")

    # Delete the record from the database
    ef.delete()
    messages.success(request, f"Deleted file “{ef.name}”.")
    return redirect('home')