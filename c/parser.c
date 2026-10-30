
#include <stdio.h>   // Stellt Funktionen für Ein- und Ausgaben bereit,
                     // z. B. printf(), fopen(), fgets() und fclose().

#include <stdlib.h>  // Stellt allgemeine Hilfsfunktionen bereit,
                     // z. B. malloc(), free(), atoi() und exit().
                     // In unserem aktuellen Code verwenden wir daraus
                     // noch keine Funktion direkt.

#include <string.h>  // Stellt Funktionen zur Verarbeitung von Zeichenketten
                     // bereit, z. B. strcmp(), strtok() und snprintf().


// --------------------------------------------------
// 1. KONSTANTEN DEFINIEREN
// --------------------------------------------------

// #define erstellt eine sogenannte Präprozessor-Konstante.
// MAX_IPS steht im gesamten Programm für den Wert 100.
// Wir können damit maximal 100 verschiedene IP-Adressen speichern.
#define MAX_IPS 100

// Maximale Länge einer einzelnen Logzeile.
// Ein Zeichen wird jeweils durch einen Speicherplatz dargestellt.
#define MAX_LENGTH 512


// --------------------------------------------------
// 2. EINE EIGENE DATENSTRUKTUR ERSTELLEN
// --------------------------------------------------

// typedef ermöglicht uns, einen eigenen Datentyp zu definieren.
// struct gruppiert mehrere Variablen zu einer gemeinsamen Struktur.
//
// Wir nennen unseren neuen Datentyp IPData.
// Er soll eine IP-Adresse und die Anzahl ihrer Fehlversuche speichern.

typedef struct {

    char ip[50];       // Zeichenarray für eine IP-Adresse.
                       // char speichert einzelne Zeichen.
                       // 50 bedeutet: maximal 50 Zeichen Speicherplatz.

    int failed_logins; // Ganze Zahl für die Anzahl fehlgeschlagener Logins.
                       // int steht für Integer (Ganzzahl).

} IPData;              // Name unseres selbst definierten Datentyps.


// --------------------------------------------------
// 3. HAUPTFUNKTION DES PROGRAMMS
// --------------------------------------------------

// main() ist der Einstiegspunkt unseres C-Programms.
// Hier beginnt die Ausführung.

int main(int argc, char *argv[]) {

    // argc = Argument Count.
    // Gibt an, wie viele Argumente beim Programmstart übergeben wurden.
    //
    // argv = Argument Vector.
    // Enthält die übergebenen Argumente als Zeichenketten.
    //
    // argv[0] enthält normalerweise den Programmnamen.
    // argv[1] enthält bei unserem Programm den Pfad zur Logdatei.


    // --------------------------------------------------
    // 4. PRÜFEN, OB EINE DATEI ÜBERGEBEN WURDE
    // --------------------------------------------------

    // Wir benötigen mindestens zwei Argumente:
    // 1. Den Programmnamen
    // 2. Den Pfad zur Logdatei
    //
    // Wenn argc kleiner als 2 ist, fehlt der Dateipfad.

    if (argc < 2) {

        // printf() gibt Text im Terminal aus.
        // \n bedeutet Zeilenumbruch.

        printf("ERROR: No log file provided.\n");

        // return 1 beendet die Funktion und signalisiert einen Fehler.
        // Die Zahl 0 wird üblicherweise für erfolgreichen Programmablauf
        // verwendet.

        return 1;
    }


    // --------------------------------------------------
    // 5. LOGDATEI ÖFFNEN
    // --------------------------------------------------

    // FILE ist ein Datentyp aus stdio.h.
    // Er repräsentiert eine geöffnete Datei.
    //
    // Das Sternchen * bedeutet, dass file ein Zeiger ist.
    // Ein Zeiger speichert eine Speicheradresse.
    //
    // fopen() öffnet eine Datei.
    //
    // argv[1] ist der übergebene Dateipfad.
    // "r" bedeutet Read Mode (Lesemodus).

    FILE *file = fopen(argv[1], "r");


    // Prüfen, ob fopen() erfolgreich war.
    //
    // Wenn die Datei nicht geöffnet werden konnte,
    // gibt fopen() den Wert NULL zurück.
    //
    // NULL bedeutet hier: Es wurde kein gültiger Datei-Zeiger geliefert.

    if (file == NULL) {

        printf("ERROR: Could not open log file.\n");

        // Programm mit Fehlerstatus beenden.
        return 1;
    }


    // --------------------------------------------------
    // 6. SPEICHER FÜR IP-ADRESSEN VORBEREITEN
    // --------------------------------------------------

    // Wir erstellen ein Array mit 100 Elementen.
    //
    // Jedes Element hat den Datentyp IPData.
    // Jedes Element kann eine IP-Adresse und einen Zähler speichern.

    IPData ips[MAX_IPS];


    // Diese Variable zählt, wie viele verschiedene IP-Adressen
    // wir bisher in unserem Array gespeichert haben.
    //
    // int = Ganzzahl.
    // Wir starten bei 0, weil noch keine IP gespeichert wurde.

    int ip_count = 0;


    // Speicherbereich für eine einzelne Logzeile.
    //
    // char = einzelnes Zeichen.
    // line ist ein Array mit 512 Zeichenplätzen.
    //
    // In diesem Array wird jeweils eine gelesene Logzeile gespeichert.

    char line[MAX_LENGTH];


    // --------------------------------------------------
    // 7. LOGDATEI ZEILE FÜR ZEILE LESEN
    // --------------------------------------------------

    // fgets() liest eine Zeile aus der geöffneten Datei.
    //
    // sizeof(line) ermittelt die Größe des Arrays.
    // file gibt an, aus welcher Datei gelesen werden soll.
    //
    // Die Schleife läuft so lange, wie fgets() erfolgreich
    // eine Zeile einlesen kann.
    //
    // Am Ende der Datei gibt fgets() NULL zurück.

    while (fgets(line, sizeof(line), file) != NULL) {


        // --------------------------------------------------
        // 8. LOGZEILE IN EINZELNE FELDER ZERLEGEN
        // --------------------------------------------------

        // Unsere Logzeilen sehen beispielsweise so aus:
        //
        // 2026-10-30 02:14:03|LOGIN_FAILED|user123|192.168.1.50|-
        //
        // Das Zeichen | dient als Trennzeichen.
        //
        // strtok() zerlegt eine Zeichenkette anhand eines Trennzeichens.
        //
        // Bei jedem Aufruf wird das nächste Feld zurückgegeben.
        // strtok() verändert dabei die ursprüngliche Zeichenkette.


        // Erstes Feld: Zeitstempel
        // Der erste Aufruf erhält die ursprüngliche Zeichenkette.

        char *timestamp = strtok(line, "|");


        // Zweites Feld: Ereignis
        // NULL bedeutet hier: Mit dem Zerlegen der vorherigen Zeichenkette
        // an der zuletzt gespeicherten Position fortfahren.

        char *event = strtok(NULL, "|");


        // Drittes Feld: Benutzername

        char *user = strtok(NULL, "|");


        // Viertes Feld: IP-Adresse

        char *ip = strtok(NULL, "|");


        // --------------------------------------------------
        // 9. FELDER AUF GÜLTIGKEIT PRÜFEN
        // --------------------------------------------------

        // Prüfen, ob alle benötigten Felder vorhanden sind.
        //
        // || bedeutet logisches ODER.
        //
        // Wenn auch nur ein Feld NULL ist, überspringen wir
        // diese fehlerhafte Logzeile.

        if (timestamp == NULL ||
            event == NULL ||
            user == NULL ||
            ip == NULL) {

            // continue beendet den aktuellen Schleifendurchlauf.
            // Danach wird direkt die nächste Logzeile gelesen.

            continue;
        }


        // --------------------------------------------------
        // 10. NUR FEHLGESCHLAGENE LOGINS BERÜCKSICHTIGEN
        // --------------------------------------------------

        // strcmp() vergleicht zwei Zeichenketten.
        //
        // Wenn beide Zeichenketten gleich sind,
        // liefert strcmp() den Wert 0.
        //
        // Wir wollen nur LOGIN_FAILED verarbeiten.
        //
        // Wenn das Ereignis NICHT LOGIN_FAILED ist,
        // überspringen wir die Zeile.
        //
        // != bedeutet: ist ungleich.

        if (strcmp(event, "LOGIN_FAILED") != 0) {

            continue;
        }


        // --------------------------------------------------
        // 11. PRÜFEN, OB DIE IP BEREITS EXISTIERT
        // --------------------------------------------------

        // found ist eine sogenannte Flag-Variable.
        //
        // Sie speichert, ob wir die IP-Adresse bereits
        // in unserem Array gefunden haben.
        //
        // 0 bedeutet: Noch nicht gefunden.
        // 1 bedeutet: Bereits gefunden.

        int found = 0;


        // for-Schleife:
        //
        // int i = 0: Wir beginnen beim ersten Array-Element.
        //
        // i < ip_count: Wir prüfen nur bereits gespeicherte IPs.
        //
        // i++: Nach jedem Durchlauf erhöhen wir i um 1.

        for (int i = 0; i < ip_count; i++) {


            // strcmp() vergleicht die aktuelle IP-Adresse
            // mit der IP-Adresse im Array.
            //
            // Wenn das Ergebnis 0 ist, sind beide IPs identisch.

            if (strcmp(ips[i].ip, ip) == 0) {


                // Die IP wurde bereits gefunden.
                // Deshalb erhöhen wir ihren Login-Fehlerzähler.
                //
                // ++ erhöht den aktuellen Wert um 1.

                ips[i].failed_logins++;


                // Markieren, dass die IP bereits existiert.

                found = 1;


                // break beendet die aktuelle for-Schleife sofort.
                //
                // Wir müssen nicht mehr nach der IP suchen,
                // weil wir sie bereits gefunden haben.

                break;
            }
        }


        // --------------------------------------------------
        // 12. NEUE IP-ADRESSE SPEICHERN
        // --------------------------------------------------

        // Wenn found weiterhin 0 ist, wurde die IP nicht gefunden.
        //
        // Zusätzlich prüfen wir, ob unser Array noch Platz hat.
        //
        // && bedeutet logisches UND.
        // Beide Bedingungen müssen wahr sein.

        if (!found && ip_count < MAX_IPS) {


            // snprintf() kopiert die IP-Adresse in unser Array.
            //
            // ips[ip_count].ip:
            // Speicherort für die neue IP-Adresse.
            //
            // sizeof(...) gibt die Größe des Zielarrays an.
            //
            // %s bedeutet, dass eine Zeichenkette eingefügt wird.
            //
            // ip ist die IP-Adresse aus der Logdatei.
            //
            // snprintf() begrenzt die Ausgabe auf die verfügbare
            // Speichergröße und verhindert so einen Pufferüberlauf.

            snprintf(
                ips[ip_count].ip,
                sizeof(ips[ip_count].ip),
                "%s",
                ip
            );


            // Die IP ist neu.
            // Deshalb setzen wir ihren Fehlversuchszähler auf 1.
            //
            // Der aktuelle Login-Versuch ist bereits der erste.

            ips[ip_count].failed_logins = 1;


            // Anzahl der gespeicherten IP-Adressen um 1 erhöhen.

            ip_count++;
        }
    }


    // --------------------------------------------------
    // 13. DATEI SCHLIESSEN
    // --------------------------------------------------

    // Nachdem wir alle Logzeilen verarbeitet haben,
    // schließen wir die Datei.
    //
    // Das ist wichtig, damit Betriebssystemressourcen
    // wieder freigegeben werden.

    fclose(file);


    // --------------------------------------------------
    // 14. ANALYSEERGEBNISSE AUSGEBEN
    // --------------------------------------------------

    // Wir durchlaufen alle gespeicherten IP-Adressen.
    //
    // i beginnt bei 0 und läuft bis ip_count.

    for (int i = 0; i < ip_count; i++) {


        // printf() gibt die IP-Adresse und ihre Fehlversuche aus.
        //
        // %s = Zeichenkette
        // %d = Ganzzahl
        // \n = Zeilenumbruch
        //
        // Das Trennzeichen | verwenden wir, damit Python
        // die Daten später einfach verarbeiten kann.

        printf(
            "%s|%d\n",
            ips[i].ip,
            ips[i].failed_logins
        );
    }


    // --------------------------------------------------
    // 15. PROGRAMM ERFOLGREICH BEENDEN
    // --------------------------------------------------

    // return 0 signalisiert, dass das Programm erfolgreich
    // ausgeführt wurde.

    return 0;
}
