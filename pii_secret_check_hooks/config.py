REPO_URL = "https://github.com/uktrade/pii-secret-check-hooks/releases/latest"

RELEASE_CHECK_URL = "https://api.github.com/repos/uktrade/pii-secret-check-hooks/releases/latest"

LINE_MARKER = "/PS-IGNORE"

IGNORE_EXTENSIONS = [
   ".png",
   ".jpg",
   ".jpeg",
   ".gif",
   ".svg",
   ".ico",
   ".eot",
   ".ttf",
   ".woff",
   ".css",
]

FILENAME_REGEX = [
   r"\.txt$",
   # Databases
   r"\.backup$",
   r"\.bak$",
   r"\.sql$",
   # Worksheets
   r"\.csv$",
   r"\.xlsx$",
   r"\.xls$",
   # Word Legacy
   r"\.doc$",
   r"\.dot$",
   r"\.wbk$",
   #  Word Office Open XML (OOXML) format
   r"\.docx$",
   r"\.docm$",
   r"\.dotx$",
   r"\.dotm$",
   r"\.docb$",
   # Excel
   r"\.xls$",
   r"\.xlt$",
   r"\.xlm$",
   #  Excel OOXML
   r"\.xlsx$",
   r"\.xlsm$",
   r"\.xltx$",
   r"\.xltm$",
   # Other formats
   r"\.xlsb$",
   r"\.xla$",
   r"\.xlam$",
   r"\.xll$",
   r"\.xlw$",
   # PowerPoint legacy
   r"\.ppt$",
   r"\.pot$",
   r"\.pps$",
   # OOXML
   r"\.pptx$",
   r"\.pptm$",
   r"\.potx$",
   r"\.potm$",
   r"\.ppam$",
   r"\.ppsx$",
   r"\.ppsm$",
   r"\.sldx$",
   r"\.sldm$",
   # Access
   r"\.accdb$",
   r"\.accde$",
   r"\.accdt$",
   r"\.accdr$",
   # OneNote
   r"\.one$",
   # Publisher
   r"\.pub$",
   # XPS Document
   r"\.xps$",
   # Adobe
   r"\.pdf$",
   r"\.ps$",
   r"\.eps$"
   r"\.prn$",
   # conf
   r"\.conf$",
   r"\.env$",
   r"\.p12$",
   r"\.pfx$",
   r"\.pkcs12$",
   r"\.pem$",
   r"_rsa$",
   r"_dsa$",
   r"]_ed25519$",
   r"_ecdsa$",
   r"\.jks$",
   # bash/zsh rc file:
   r"^\.?(bash|zsh)?rc$",
   # bash/zsh profile:
   r"^\.?(bash|zsh)_profile$",
   # bash/zsh aliases file:
   r"^\.?(bash|zsh)_aliases$",
   # credential(s) file:
   r"^\.credential(s)?$",
   # Github Enterprise file:
   r"^\.githubenterprise$",
   # Apple Keychain file:
   r"^\.*keychain$",
   # Keystore/Keyring file:
   r"^key(store|ring)$",
   # Keepass secret file
   r"^\.*kdb",
]

PII_REGEX = {
   "'First name'": r"(\s*)first(\s*)name(\s*)",
   "'Last name'": r"(\s*)last(\s*)name(\s*)",
   "'Postcode'": r"([Gg][Ii][Rr] 0[Aa]{2})|((([A-Za-z][0-9]{1,2})|(([A-Za-z][A-Ha-hJ-Yj-y][0-9]{1,2})|(([A-Za-z][0-9][A-Za-z])|([A-Za-z][A-Ha-hJ-Yj-y][0-9][A-Za-z]?))))\s?[0-9][A-Za-z]{2})",
   "'Email'": r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
}

NER_IGNORE = [
   "DATE", "CARDINAL", "MONEY", "ORDINAL", "PERCENT", "TIME", "GPE",
]

NER_EXCLUDE = [
   "UnicodeDecoder",
   "S3",
   "Django",
   "Redis",
   "CACHES",
   "DEFAULT_DOMAIN",
   "False",
   "email.eu-west-1.amazonaws.com",
   "Email",
   "JavaScript",
   "CSS",
   "NOQA",
   "Password",
   "BCryptSHA256PasswordHasher",
   "Django 2.1.7",
   "File",
   "get_object_or_404",
   "HttpResponse",
   "PermissionDenied",
   "django.contrib",
   "django.conf import settings",
   "CharField",
   "DecimalField",
   "ForeignKey",
   "TextField",
   "List",
   "QuerySet",
   "Task",
   "TextChoices",
   "sys",
   "Menu",
   "NamedTuple",
   "DatabaseError",
   "HttpRequest",
   "TestCase",
   "DateField",
   "BooleanField",
   "Faker",
   "Template",
   "Meta",
   "utc",
   "LazyAttribute",
   "TODO",
   "TypeError",
   "ValueError",
   "Model",
   "Markup",
   "RadioSelectInline",
   "ValidationError",
   "ModelChoiceField",
   "Optional",
   "ChoiceField",
   "structlog",
   "Notes",
   "Exception",
   "Statistics",
   "Unarchive",
   "Callable",
   "TemplateView",
   "data=",
   "BaseCommand",
   "ModelUpdateView",
   "ModelCreateView",
   "ModelDetailView",
   "ListView",
   "TypedDict",
   "ChoiceFilter",
   "Client",
   "UserFactory",
   "CharFilter",
   "FilterSet",
   "FILES",
   "None",
   "DateInput",
   "choices=",
   "FormData",
   "Client",
   "System",
   "TYPES",
   "Optional",
   "Category",
   "MOBILE",
   "TYPES",
   "UserManager",
   "Blocked",
   "TEMPORARY",
   "Temporary",
   "FileField",
   "Overridden",
   "ListAction",
   "DetailView",
   "SuspiciousOperation",
   "CreateView",
   "ListView",
   "UpdateView",
   "EmptyPage",
   "RuntimeError",
   "INDIVIDUAL",
   "COMPLETED",
   "DocumentForm",
   "SubmitForm",
   "PDF",
   "Invalid",
   "SubTypes",
   "FuzzyChoice",
   "Unarchive",
   "COMPLETED",
   "ValidationError",
   "ModelChoiceField",
   "STATUS",
   "UTC",
   "Callable",
   "Mailshot",
   "TYPES",
   "DATE_FORMAT",
   "LABEL",
   "Submit",
   "DocumentForm",
   "ArrayField",
   "Mock",
   "AppConfig",
   "Types",
   "DateInput",
   "AWS_SES_ACCESS_KEY_ID",
   "AWS_SECRET_ACCESS_KEY",
   "BaseFormSet",
   "config",
   "COPY",
   "RUN",
   "FixtureData",
   "ModelFilterView",
   "Byte",
   "USE_L10N",
   "PRIMARY",
   "CheckboxSelectMultiple",
   "CommandError",
   "AUTO",
   "@require_GET",
   "ContentType",
   "CustomError",
   "CSV",
   "OrderedDict",
   "PhoneNumberField",
   "TextInput",
   "Select",
   "PasswordInput",
   "ModelForm",
   "import pytz",
]
