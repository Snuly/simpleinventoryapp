<h3 align="center">Vienkārša Inventāra Aplikācija</h3>

---

<p align="center"> Vienkārša un viegli uzstādāma inventāra parvaldības lokāla web lietotne. 
    <br> 
</p>

## 📝 Saturs
- [Par](#about)
- [Iesākums](#getting_started)
- [Priekšnotekumi](#pre)
- [Uzstādīšana](#install)
- [Izmantošana](#usage)
- [Izveidots izmantojot](#built_using)
- [Autors](#authors)

## 🧐 Par <a name = "about"></a>
Applikācija ir veidota maziem biznesiem vai personām, kas vēlas elektroniski pārvaldīt savu inventāru ar iespēju pievienot vairākus lietotājus. Lietotāja saskarne ir vienkārša un viegli saprotama, tā ļauj pievienot, dzēst un rediģēt inventāra vienības, kā arī pārvaldīt lietotājus ar dažādām tiesībām. Tā nodrošina arī lietotāju autentifikāciju un administratīvos rīkus.

## 🏁 Iesākums <a name = "getting_started"></a>
Šīs instrukcijas palīdzēs iegūt projekta kopiju un palaist to uz jūsu vietējā datora.

### Priekšnoteikumi <a name = "pre"></a>
Lai palaistu šo lietotni, jums būs nepieciešams:

<b>Python</b> - Instalējiet Python jaunāko versiju no www.python.org/downloads/<br>
<b>pip</b> - Python pakotņu pārvaldnieks, kas ir instalēts kopā ar Python.<br>
<b>SQLite</b> - Datubaze, nāk kopa ar python installaciju

### Uzstādīšana <a name = "install"></a>
1. Pārliecinieties, ka jums ir instalēta vismaz Python versija 3.6 vai jaunāka.
2. Lejupielādējiet šo projektu un pārejiet uz direktoriju, kur tas atrodas. Ja tā ir zip mape, tad atpako to vispirms.
3. Atveriet failu <b>installprerequisite.bat</b> vai manuali instalējiet Python preikšnoteikumus atverot Command Prompt un ierakstot šadu komandu:
```
pip install flask flask_limiter flask_wtf
```
4. Atveriet failu <b>run.bat</b> lai sāktu web aplikāciju, vai manuali sāciet applikāciju caur Command Prompt izmantojot komandu:
```
python -m flask --app app.py run --host=0.0.0.0
```
5. Ja viss ir pareizi konfigurēts, aplikācija būs pieejama vietējā serverī http://127.0.0.1:5000/. 
![image](https://github.com/user-attachments/assets/38e01520-f630-465c-82bd-4f4d3d0bb9ed)


## 🎈 Izmantošana <a name="usage"></a>
Pēc noklusējuma būs izveidots admin lietotājs, pieslēdzies tam lai tiktu pie sistēms.
```
Lietotājvārds: admin
Parole: admin
```


## ⛏️ Izveidots, izmantojot <a name = "built_using"></a>
- [Python](https://www.python.org) - Programmēšanas valoda
- [Flask](https://flask.palletsprojects.com/en/stable/) - Web framework(ietvars)
- [SQLite](https://www.sqlite.org) - Datu bāze
- [Bootstrap](https://getbootstrap.com) - CSS framework(ietvars)
- [Flask-WTF](https://flask-wtf.readthedocs.io/en/1.2.x/) - Flask paplašinājums
- [Flask-Session](https://flask-session.readthedocs.io/en/latest/) - Flask paplašinājums
- [Flask-Limiter](https://flask-limiter.readthedocs.io/en/stable/) - Flask paplašinājums

## ✍️ Autors <a name = "authors"></a>
- [@Snuly](https://github.com/Snuly)
