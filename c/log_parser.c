
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Maximale Anzahl verschiedener IP-Adressen
#define MAX_IPS 100

// Maximale Länge einer Logzeile
#define MAX_LENGTH 512

// Maximale Länge einer IP-Adresse
#define IP_LENGTH 50


// --------------------------------------------------
// DATENSTRUKTUR
// --------------------------------------------------

// Speichert eine IP-Adresse und ihre Fehlversuche
typedef struct {

    char ip[IP_LENGTH];
    int failed_logins;

} IPData;


// --------------------------------------------------
// FUNKTION 1: LOGDATEI ÖFFNEN
// --------------------------------------------------

// Öffnet eine Datei im Lesemodus.
// Gibt einen FILE-Zeiger zurück, wenn es funktioniert.
// Gibt NULL zurück, wenn ein Fehler auftritt.

FILE* open_log_file(const char *filename) {

    FILE *file = fopen(filename, "r");

    if (file == NULL) {

        printf("ERROR: Could not open log file.\n");

        return NULL;
    }

    return file;
}


// --------------------------------------------------
// FUNKTION 2: IP-ADRESSE SUCHEN
// --------------------------------------------------

// Durchsucht das Array nach einer bestimmten IP-Adresse.
// Gibt den Index zurück, wenn die IP gefunden wurde.
// Gibt -1 zurück, wenn sie nicht existiert.

int find_ip(IPData ips[], int ip_count, const char *ip) {

    for (int i = 0; i < ip_count; i++) {

        if (strcmp(ips[i].ip, ip) == 0) {

            return i;
        }
    }

    return -1;
}


// --------------------------------------------------
// FUNKTION 3: IP-ADRESSE VALIDIEREN
// --------------------------------------------------

// Prüft, ob eine Zeichenkette eine gültige IPv4-Adresse ist.
//
// Rückgabewert:
// 1 = IP-Adresse ist gültig
// 0 = IP-Adresse ist ungültig

int is_valid_ip(const char *ip) {

    // Wir prüfen genau vier Zahlenblöcke
    for (int octet = 0; octet < 4; octet++) {

        // Wert des aktuellen Zahlenblocks
        int value = 0;

        // Anzahl der gelesenen Ziffern
        int digits = 0;

        // Prüfen, ob überhaupt eine Ziffer vorhanden ist
        if (*ip == '\0') {

            return 0;
        }

        // Alle Ziffern des aktuellen Zahlenblocks einlesen
        while (*ip >= '0' && *ip <= '9') {

            // Ein Zahlenblock darf maximal drei Ziffern haben
            if (digits >= 3) {

                return 0;
            }

            // Zeichen in einen Zahlenwert umwandeln
            value = value * 10 + (*ip - '0');

            // Prüfen, ob der Zahlenwert größer als 255 ist
            if (value > 255) {

                return 0;
            }

            digits++;

            // Zum nächsten Zeichen springen
            ip++;
        }

        // Ein Zahlenblock muss mindestens eine Ziffer enthalten
        if (digits == 0) {

            return 0;
        }

        // Nach den ersten drei Zahlenblöcken muss ein Punkt stehen
        if (octet < 3) {

            if (*ip != '.') {

                return 0;
            }

            // Punkt überspringen
            ip++;

        } else {

            // Nach dem vierten Zahlenblock darf nichts mehr kommen
            if (*ip != '\0') {

                return 0;
            }
        }
    }

    // Alle vier Zahlenblöcke waren gültig
    return 1;
}


// --------------------------------------------------
// FUNKTION 4: IP-ADRESSE SPEICHERN
// --------------------------------------------------

// Erhöht den Zähler einer vorhandenen IP-Adresse.
// Oder erstellt einen neuen Eintrag.

void update_ip(IPData ips[], int *ip_count, const char *ip) {

    // Prüfen, ob die IP bereits existiert
    int index = find_ip(ips, *ip_count, ip);

    if (index != -1) {

        // IP existiert bereits: Zähler erhöhen
        ips[index].failed_logins++;

    } else {

        // Prüfen, ob noch Platz im Array vorhanden ist
        if (*ip_count >= MAX_IPS) {

            printf("WARNING: Maximum number of IPs reached.\n");

            return;
        }

        // Neue IP-Adresse speichern
        snprintf(
            ips[*ip_count].ip,
            IP_LENGTH,
            "%s",
            ip
        );

        // Ersten Fehlversuch eintragen
        ips[*ip_count].failed_logins = 1;

        // Anzahl gespeicherter IPs erhöhen
        (*ip_count)++;
    }
}


// --------------------------------------------------
// FUNKTION 5: EINZELNE LOGZEILE VERARBEITEN
// --------------------------------------------------

void process_log_line(
    char *line,
    IPData ips[],
    int *ip_count
) {

    // Zeilenumbrüche am Ende der Logzeile entfernen
    line[strcspn(line, "\r\n")] = '\0';

    // Logzeile in einzelne Felder aufteilen
    char *timestamp = strtok(line, "|");
    char *event = strtok(NULL, "|");
    char *user = strtok(NULL, "|");
    char *ip = strtok(NULL, "|");

    // Prüfen, ob alle Felder vorhanden sind
    if (
        timestamp == NULL ||
        event == NULL ||
        user == NULL ||
        ip == NULL
    ) {

        return;
    }

    // Nur fehlgeschlagene Logins verarbeiten
    if (strcmp(event, "LOGIN_FAILED") != 0) {

        return;
    }

    // Prüfen, ob die IP-Adresse gültig ist
    if (!is_valid_ip(ip)) {

        printf("WARNING: Invalid IP address: %s\n", ip);

        return;
    }

    // IP-Adresse speichern oder ihren Zähler erhöhen
    update_ip(ips, ip_count, ip);
}


// --------------------------------------------------
// FUNKTION 6: GESAMTE LOGDATEI VERARBEITEN
// --------------------------------------------------

void process_log_file(
    FILE *file,
    IPData ips[],
    int *ip_count
) {

    // Speicher für eine einzelne Logzeile
    char line[MAX_LENGTH];

    // Jede Zeile der Datei einzeln lesen
    while (fgets(line, sizeof(line), file) != NULL) {

        process_log_line(line, ips, ip_count);
    }
}


// --------------------------------------------------
// FUNKTION 7: ERGEBNISSE AUSGEBEN
// --------------------------------------------------

void print_results(IPData ips[], int ip_count) {

    printf("\nSECURITY ANALYSIS RESULTS\n");

    printf("------------------------------\n");

    // Alle gespeicherten IP-Adressen ausgeben
    for (int i = 0; i < ip_count; i++) {

        printf(
            "%s|%d\n",
            ips[i].ip,
            ips[i].failed_logins
        );
    }

    printf("------------------------------\n");
}


// --------------------------------------------------
// HAUPTFUNKTION
// --------------------------------------------------

int main(int argc, char *argv[]) {

    // Prüfen, ob ein Dateipfad übergeben wurde
    if (argc < 2) {

        printf("ERROR: No file specified.\n");

        return 1;
    }

    // Logdatei öffnen
    FILE *file = open_log_file(argv[1]);

    if (file == NULL) {

        return 1;
    }

    // Array für die IP-Adressen erstellen
    IPData ips[MAX_IPS];

    // Anzahl gespeicherter IP-Adressen
    int ip_count = 0;

    // Logdatei analysieren
    process_log_file(file, ips, &ip_count);

    // Datei schließen
    fclose(file);

    // Ergebnisse ausgeben
    print_results(ips, ip_count);

    return 0;
}
