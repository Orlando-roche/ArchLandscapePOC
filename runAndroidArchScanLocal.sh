#export ANDROID_REPO=~/code/your-android-project
python archscan_Android.py --repo ../android-mobile-research-platform --out outputs/android-afm.json --diagram outputs/android.mmd
python validate_afm.py --afm outputs/android-afm.json --schema afm_schema.json --allowlist config/allowed_issuers.txt