from django.contrib import admin

from .models import EncryptedFile
from .models import EncryptedFile, UserProfile
# Register your models here.


@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'upload_ts')
    readonly_fields = ('nonce', 'tag', 'ciphertext')


admin.site.register(UserProfile)
