; Instalador de Windows, con Inno Setup 6. Lo compila la CI después de PyInstaller:
;     iscc packaging\windows\pcap-hunter.iss
; La versión llega en la variable de entorno PCAPHUNTER_VERSION.

#define AppVersion GetEnv("PCAPHUNTER_VERSION")

[Setup]
; Este identificador no se cambia nunca: es lo que hace que una versión nueva se instale
; encima de la anterior en vez de al lado.
AppId={{6387B9D8-DCE0-4700-A47E-CFE967D98BC8}
AppName=pcap-hunter
AppVersion={#AppVersion}
AppVerName=pcap-hunter {#AppVersion}
AppPublisher=espi0207
AppPublisherURL=https://github.com/espi0207/pcap-hunter
AppSupportURL=https://github.com/espi0207/pcap-hunter/issues
DefaultDirName={autopf}\pcap-hunter
DisableProgramGroupPage=yes
; Sin permisos de administrador se instala solo para quien lo instala (y no sale el aviso
; de "¿Quieres permitir que esta aplicación haga cambios?").
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=pcap-hunter-windows
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\pcap-hunter.exe
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesAssociations=yes

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "openwith"; Description: "Añadir pcap-hunter a «Abrir con» en las capturas .pcap y .pcapng"
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; Flags: unchecked

[Files]
Source: "..\..\dist\pcap-hunter\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\pcap-hunter"; Filename: "{app}\pcap-hunter.exe"
Name: "{autodesktop}\pcap-hunter"; Filename: "{app}\pcap-hunter.exe"; Tasks: desktopicon

[Registry]
; pcap-hunter sale en "Abrir con" de las capturas, pero no se queda con ellas: quien tenga
; Wireshark las sigue abriendo con Wireshark al hacer doble clic.
Root: HKA; Subkey: "Software\Classes\PcapHunter.Captura"; ValueType: string; ValueName: ""; ValueData: "Captura de red"; Flags: uninsdeletekey; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\PcapHunter.Captura\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\pcap-hunter.exe,0"; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\PcapHunter.Captura\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\pcap-hunter.exe"" ""%1"""; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\.pcap\OpenWithProgids"; ValueType: string; ValueName: "PcapHunter.Captura"; ValueData: ""; Flags: uninsdeletevalue; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\.pcapng\OpenWithProgids"; ValueType: string; ValueName: "PcapHunter.Captura"; ValueData: ""; Flags: uninsdeletevalue; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\.cap\OpenWithProgids"; ValueType: string; ValueName: "PcapHunter.Captura"; ValueData: ""; Flags: uninsdeletevalue; Tasks: openwith

[Run]
Filename: "{app}\pcap-hunter.exe"; Description: "Abrir pcap-hunter"; Flags: nowait postinstall skipifsilent
