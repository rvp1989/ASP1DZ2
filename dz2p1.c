#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Maksimalan broj karaktera koji moze imati ime i prezime korisnika, moze se i povecati ako je potrebno
#define MAX_IME 50

// Svaki interni cvor ce kao vrstu cvora imati karakter 'i', a eksterni karater 'e', kako ne bi koristili stalno karaktere bolje ovako konstantu da uvedemo
#define I 'i'
#define E 'e'

// Ova konstanta se koristi prilikom ispisa stabla
#define BROJ_RAZMAKA_PO_NIVOU 10
 
// Tip strukture koja se koristi za svaku Osobu, odnosno ucesnika turnira, u promenljivoj ime se smesta ime i prezime, a promenljiva nosilac je njegov redni broj prilikom formiranja stabla
typedef struct Osoba {
	char ime[MAX_IME];
	int nosilac;
} Osoba;

// Opisuje svaki cvor u stablu, u okviru cvora pamtimo njegovu vrstu (I/E), zatim nivo na kom se cvor nalazi (pogodno za ispis stabla, internu duzinu puta i ispis svih potencijalnih parova)
// Promenljiva podaci je genericki pokazivac, koji u zavisnosti od vrste cvora pokazuje ili na Interni ili na Eksterni cvor
// Smatra se da koren stabla ima nivo 0, njegovi sinovi 1, itd.
typedef struct Cvor {
	void* podaci;
	char vrsta;
	int nivo;
} Cvor;

// Interni cvor sadrzi poene jednog i drugog takmicara (vr1 i vr2), pokazivac na Osobu koja je pobedila odnosno ciji je broj poena veci, i sadrzi pokazivace na levi i desni cvor, interni cvorovi uvek imaju oba sina
typedef struct Interni {
	int vr1, vr2;
	Osoba* pobednik;

	Cvor* l, *d;
} Interni;

// Eksterni cvor sadrzi iskljucivo pokazivac na osobu koja ucestvuje na turniru, on nema sinove
typedef struct Eksterni {
	Osoba* osoba;
} Eksterni;

// Element jednostruko ulancane liste koja ce se koristiti u implementaciji reda i steka, koji su potrebni za obilaske stabla
typedef struct ListaElem {
	Cvor* info;
	struct ListaElem* sled;
} ListaElem;

// FIFO red implementiran pomocu pokazivaca na pocetak i kraj liste koja ga cini, takodje pamti se i broj elemenata koji se trenutno nalaze u redu
typedef struct Red {
	ListaElem* pocetak, *kraj;
	int broj;
} Red;

// LIFO stek implementiran pomocu pokazivaca na pocetak liste koja ga cini, takodje pamti se i broj elemenata koji se trenutno nalaze na steku
typedef struct Stek {
	ListaElem* vrh;
	int broj;
} Stek;



/*
Ova funkcija se poziva kada god je alokacija prostora neuspesna
*/
void greskaAlokacijaProstora() {
	system("cls");
	printf("NEMA DOVOLJNO MEMORIJE. GRESKA U ALOKACIJI PROSTORA.\n");
	exit(1);
}

int stekPrazan(Stek* stek) {
	return stek->vrh == NULL;
}

void inicijalizujStek(Stek* stek) {
	stek->vrh = NULL;
	stek->broj = 0;
}

/*
	Ubacivanje cvora na vrh steka
*/
void dodajStek(Stek* stek, Cvor *cvor) {
	ListaElem* novi;

	novi = (ListaElem*)malloc(sizeof(ListaElem));
	novi->info = cvor;
	novi->sled = stek->vrh;

	stek->vrh = novi;

	stek->broj = stek->broj + 1;
}

/*
	Skidanje cvora sa vrha steka
*/
Cvor* uzmiStek(Stek* stek) {
	Cvor* info;
	ListaElem* zaBrisanje;

	if (stekPrazan(stek)) {
		return NULL;
	}

	info = stek->vrh->info;

	zaBrisanje = stek->vrh;

	stek->vrh = stek->vrh->sled;

	// Oslobadja se iskljucivo prostor rezervisan za element liste koja cini stek, nikako se ne sme dealocirati cvor stabla
	free(zaBrisanje);

	stek->broj = stek->broj - 1;

	return info;
}


int redPrazan(Red* red) {
	return red->pocetak == NULL;
}

void inicijalizujRed(Red* red) {
	red->pocetak = NULL;
	red->kraj = NULL;
	red->broj = 0;
}

/*
	Funkcija za ubacivanje Cvora na kraj reda
*/
void dodajRed(Red* red, Cvor* cvor) {
	ListaElem* novi;

	novi = (ListaElem*) malloc(sizeof(ListaElem));
	novi->info = cvor;
	novi->sled = NULL;

	if (red->pocetak == NULL) {
		red->pocetak = novi;
	}
	else {
		red->kraj->sled = novi;
	}

	red->kraj = novi;

	red->broj = red->broj + 1;
}

/*
	Funkcija za uklanjanje cvora sa pocetka reda
*/
Cvor* uzmiRed(Red* red) {
	Cvor* info;
	ListaElem* zaBrisanje;

	if (redPrazan(red)) {
		return NULL;
	}

	info = red->pocetak->info;

	zaBrisanje = red->pocetak;

	red->pocetak = red->pocetak->sled;

	if (red->pocetak == NULL) {
		red->kraj = NULL;
	}
	
	// Oslobadja se iskljucivo prostor rezervisan za element liste koja cini red, nikako se ne sme dealocirati cvor stabla
	free(zaBrisanje);

	red->broj = red->broj - 1;
	
	return info;
}

/*
	Prilikom brisanja internog cvora nikako ne treba brisati osobu na koju on pokazuje, da ne bi doslo do visestrukog brisanja, osobu je dovoljno izbrisati samo jednom prilikom brisanja eksternog cvora
*/
void dealocirajInterni(Interni* interni) {
	free(interni);
}

/*
	Funkcija za alokaciju prostora za novi interni cvor stabla koji ce u sebi sadrzati pokazivac na osobu pobednika i vrednost nivoa na kojem se cvor formira
*/
Interni* alocirajInterni(Osoba* osoba, int nivo) {
	Cvor* cvor; 
	Interni* interni; 

	cvor = (Cvor*)malloc(sizeof(Cvor));

	if (cvor == NULL) {
		greskaAlokacijaProstora();
	}

	interni = (Interni*)malloc(sizeof(Interni));

	if (interni == NULL) {
		greskaAlokacijaProstora();
	}

	cvor->podaci = interni;
	cvor->nivo = nivo;
	cvor->vrsta = I;

	//Prilikom formiranja stabla kao rezultati meceva postavljaju se vrednosti 0:0, a kao pobednik je zapamcen cvor koji je bolji nosilac(niza vrednost je bolja), sto ce nam znaciti prilikom formiranja stabla
	interni->l = NULL;
	interni->d = NULL;
	interni->vr1 = 0;
	interni->vr2 = 0;
	interni->pobednik = osoba;

	return cvor;
}

/*
	Prilikom brisanja eksternog cvora potrebno je osloboditi memoriju rezervisanu i za osobu na koju je on pokazivao
*/
void dealocirajEksterni(Eksterni* eksterni) {
	free(eksterni->osoba);
	free(eksterni);
}

/*
	Funkcija koja stvara novi eksterni cvor koji ukazuje na osobu koja je ucesnik turnira, uz nivo na koje se eksterni cvor nalazi
*/
Eksterni* alocirajEksterni(Osoba* osoba, int nivo) {
	Cvor* cvor;
	Eksterni* eksterni; 

	cvor = (Cvor*)malloc(sizeof(Cvor));

	if (cvor == NULL) {
		greskaAlokacijaProstora();
	}

	eksterni = (Eksterni*)malloc(sizeof(Eksterni));

	if (eksterni == NULL) {
		greskaAlokacijaProstora();
	}

	cvor->podaci = eksterni;
	cvor->nivo = nivo;
	cvor->vrsta = E;

	eksterni->osoba = osoba;

	return cvor;
}

/*
	Funkcija za formiranje stabla koja vraca pokazivac na njegov koren i inicijalizuje promenljivu n sa brojem ucesnika na turniru
*/
Interni* formirajStablo(int* n) {
	int kraj;
	Red red;
	int brojNivoa;
	int brojCvorovaNivo;
	int brojPretposlednjiNivo;
	int i;
	int j;
	int kompletnoStablo;
	int brojRed;

	Osoba** osobe;
	Cvor* koren;

	Cvor* tekuci;
	Interni* interniTekuci, levi, desni;

	system("cls");

	do {
		kraj = 1;
		printf("Unesite broj ucesnika na turniru: ");
		scanf("%d", n);

		if (*n < 2) {
			printf("Broj ucesnika turnira mora biti minimum 2. Ponovite unos.\n\n");
			kraj = 0;
		}
	} while (!kraj);

	// Posto je stablo puno, broj nivoa se uvek zaokruzuje na gornji ceo deo logaritma
	brojNivoa = ceil(log2(*n)) + 1;

	// Broj eksternih cvorova u pretposlednjem nivou, sto znaci da su ti igraci slobodni u prvoj rundi i cekaju pobednike te runde u drugoj
	brojPretposlednjiNivo = pow(2, ceil(log2(*n))) - *n;

	// Za pocetak alociramo niz pokazivaca na osobe ciji se podaci unose sa konzole. Ovaj niz treba kasnije pretociti u stablo.
	osobe = (Osoba**) calloc(*n, sizeof(Osoba*));

	if (osobe == NULL) {
		greskaAlokacijaProstora();
	}

	// scanf ostavlja newline u baferu za citanje pa da ga gets ne bi progutao u for petlji moramo jedan vestacki gets
	// https://stackoverflow.com/questions/26175715/gets-function-in-c-not-waiting-for-input
	gets();

	// Unos ucesnika turnira po nosiocima
	for (i = 0; i < *n; i++) {
		osobe[i] = (Osoba*) malloc(sizeof(Osoba));
		osobe[i]->nosilac = i + 1;

		if (osobe[i] == NULL) {
			greskaAlokacijaProstora();
		}

		printf("Unesite ime i prezime %d.-og nosioca:", i + 1);
		gets(osobe[i]->ime);	
	}

	// Koren je uvek interni cvor, jer turnir mora imati minimum 2 ucesnika
	koren = alocirajInterni(osobe[0], 0);

	// Stablo cemo formirati primenom Level order obilaska stoga nam je potreban red
	inicijalizujRed(&red);

	dodajRed(&red, koren);

	// U red ce biti ubacivani samo interni cvorovi, stoga imamo manje nivoa za obilazak
	for (i = 1; i <= brojNivoa - 1; i++) {
		brojRed = red.broj;

		brojCvorovaNivo = pow(2, i);

		// Za sve elemente koji se trenutno nalaze u redu, u redu su samo elementi trenutnog nivoa
		for (j = 0; j < brojRed; j++) {
			tekuci = uzmiRed(&red);

			interniTekuci = ((Interni*)tekuci->podaci);

			// Ukoliko smo na pretposlednjem nivou (i == brojNivoa - 1) za levog i desnog sina trenutnog cvora sigurno treba da alociramo eksterne cvorove, jer se samo eksterni cvorovi nalaze na nivou ispod pretposlednjeg
			// Ukoliko smo na 2 nivoa iznad poslednjeg (i == brojNivoa - 2) i ukoliko vazi da je redni broj nosioca (koji ce biti u sledecem nivou ucesnik meca), manji ili jednak od broja eksternih cvorova u pretposlednjem nivou, onda sa leve strane treba alocirati eksterni cvor
			if ((i == brojNivoa - 1) || (i == brojNivoa - 2 && interniTekuci->pobednik->nosilac <= brojPretposlednjiNivo)) {
				// alociranje eksternog cvora kao levog sina
				interniTekuci->l = alocirajEksterni(interniTekuci->pobednik, i);

				// desni sin takodje treba biti eksterni cvor ako smo u pretposlednjem nivou ili ako je i njegov redni broj nosioca manji ili jednak od broja eksternih cvorova u pretposlednjem nivou
				if ( (i == brojNivoa - 1) || brojCvorovaNivo - interniTekuci->pobednik->nosilac + 1 <= brojPretposlednjiNivo) {
					interniTekuci->d = alocirajEksterni(osobe[brojCvorovaNivo - interniTekuci->pobednik->nosilac], i);
				}
				// u suprotnom desni sin je interni cvor i dodaje se u red za obilazak
				else {
					interniTekuci->d = alocirajInterni(osobe[brojCvorovaNivo - interniTekuci->pobednik->nosilac], i);
					dodajRed(&red, interniTekuci->d);
				}
			}
			// ako smo negde u sredini stabla za decu alociramo interne cvorove i dodajemo ih u red za obilazak
			else {
				interniTekuci->l = alocirajInterni(interniTekuci->pobednik, i);
				interniTekuci->d = alocirajInterni(osobe[brojCvorovaNivo - interniTekuci->pobednik->nosilac], i);
				dodajRed(&red, interniTekuci->l);
				dodajRed(&red, interniTekuci->d);
			}
		}
	}

	// Oslobanje prostora za niz osoba, jer je taj niz pretocen u stablo
	free(osobe);

	return koren;
}

/*
	Rezultati turnira se moraju uneti od dole na gore i sa leva na desno po rundama, sto je nezgodno jer stablo ne poseduje pokazivace na roditelje.
	Zbog toga se vrsi Level order obilazak sa desna na levo, a pritom se svaki od elemenata koji smo obisli dodaje na stek, na kraju ce se na steku nalaziti svi interni cvorovi, ali u poretku koji nama treba i mozemo skidati jedan po jedan i popunjavati rezultate.
	Na steku za popunjavanje rezultata nece biti eksternih cvorova jer oni predstavljaju samo ucesnike turnira a ne rezultate meceva.
*/
void unosRezultataTurnira(Cvor* koren) {
	Red red;
	Stek stek;
	Cvor* tekuci;
	Interni* tekuciInterni;
	int runda, tekuciNivo;
	Osoba* osoba1, *osoba2;
	int rez1, rez2;
	int kraj;

	system("cls");

	// Red se koristi za Level Order sa desna na levo
	inicijalizujRed(&red);
	// Stek se koristi za unos rezultata meceva od dole na gore nakon sto se popuni svim internim cvorovima tokom Level order obilaska
	inicijalizujStek(&stek);

	dodajRed(&red,koren);
	dodajStek(&stek, koren);

	while (!redPrazan(&red)) {
		tekuci = uzmiRed(&red);

		tekuciInterni = ((Interni*)tekuci->podaci);

		// Ukoliko se radi o eksternom cvoru ne dodajemo ga ni u red ni na stek

		// Prvo u red i na stek dodajemo desnog sina
		if (tekuciInterni->d->vrsta != E) {
			dodajRed(&red, tekuciInterni->d);
			dodajStek(&stek, tekuciInterni->d);
		}

		// Nakon toga u red i na stek dodajemo levog sina
		if (tekuciInterni->l->vrsta != E) {
			dodajRed(&red, tekuciInterni->l);
			dodajStek(&stek, tekuciInterni->l);
		}
	}

	runda = 0;
	tekuciNivo = -1;

	while (!stekPrazan(&stek)) {
		// Sa steka skidamo interni cvor ciji rezultat popunjavamo, u cvoru pamtimo sam nivo prilikom formiranja stabla, tako da na osnovu toga znamo koja je runda u pitanju
		tekuci = uzmiStek(&stek);

		tekuciInterni = ((Interni*)tekuci->podaci);

		if (tekuci->nivo != tekuciNivo) {
			tekuciNivo = tekuci->nivo;
			runda++;
			printf("Runda %d\n==============================================\n", runda);
		}

		// Ukoliko je prvi ucesnik meca eksterni cvor, iz njega izvlacimo podatke o osobi
		if (tekuciInterni->l->vrsta == E) {
			osoba1 = ((Eksterni*)tekuciInterni->l->podaci)->osoba;
		}
		// Ukoliko je prvi ucesnik meca interni cvor, iz njega izvlacimo podatke o osobi koja je pobedila u prethodnom mecu
		else {
			osoba1 = ((Interni*)tekuciInterni->l->podaci)->pobednik;
		}

		// Sve isto vazi i za drugog ucesnika meca
		if (tekuciInterni->d->vrsta == E) {
			osoba2 = ((Eksterni*)tekuciInterni->d->podaci)->osoba;
		}
		else {
			osoba2 = ((Interni*)tekuciInterni->d->podaci)->pobednik;
		}

		do {
			kraj = 1;
			printf("(%d) %s vs. (%d) %s:", osoba1->nosilac, osoba1->ime, osoba2->nosilac, osoba2->ime);
			scanf("%d%d", &rez1, &rez2);
			if (rez1 == rez2) {
				printf("Neko mora imati vise poena. Ponovite unos.\n");
				kraj = 0;
			}
			
		} while (!kraj);
		
		tekuciInterni->vr1 = rez1;
		tekuciInterni->vr2 = rez2;

		if (tekuciInterni->vr1 > tekuciInterni->vr2) {
			tekuciInterni->pobednik = osoba1;
		}
		else {
			tekuciInterni->pobednik = osoba2;
		}
	}
}

/*
	Stablo se ispisuje u konzoli sa leva na desno, kako bi bilo bolje formatirano i posto je konzola ogranicene sirine bolje je da stablo zauzima veci vertikalni prostor jer moze da se skroluje.
	Takodje ovaj ispis je pogodan, jer se jedan cvor ispisuje u jednom redu, s tim sto se u prvom redu ispisuje krajnji desni cvor. Ovo je bitno jer se pored svakog internog cvora treba ispisati redni broj nosioca pobednik i rezultat, dok se kod svakog eksternog treba ispisati broj nosioca i ime i prezime ucesnika
	Koristimo stek i primenjujemo inverzni Inorder obilazak sa desne na levo
*/
void ispisStabla(Cvor* koren) {
	Stek stek;
	Cvor* tekuci;
	Interni* tekuciInterni;
	Eksterni* tekuciEksterni;

	system("cls");

	inicijalizujStek(&stek);

	tekuci = koren;

	while (1) {
		while (tekuci != NULL) {
			dodajStek(&stek, tekuci);
			
			if (tekuci->vrsta == E) {
				tekuci = NULL;
			}
			else {
				tekuci = ((Interni*)tekuci->podaci)->d;
			}
		}

		if (!stekPrazan(&stek)) {
			tekuci = uzmiStek(&stek);

			// U svakom cvoru pamtimo njegov nivo i udaramo tekuci->nivo * BROJ_RAZMAKA_PO_NIVOU razmaka pre ispisa sadrzaja cvora
			for (int i = 0; i < tekuci->nivo*BROJ_RAZMAKA_PO_NIVOU; i++){
				printf(" ");
			}

			// Ispis sadrzaja eksternog cvora
			if (tekuci->vrsta == E) {
				tekuciEksterni = ((Eksterni*)tekuci->podaci);
				printf("%d (%s)\n", tekuciEksterni->osoba->nosilac, tekuciEksterni->osoba->ime);
				tekuci = NULL;
			}
			// Ispis sadrzaja internog cvora
			else {
				tekuciInterni = ((Interni*)tekuci->podaci);
				printf("%d (%d:%d)\n", tekuciInterni->pobednik->nosilac, tekuciInterni->vr1, tekuciInterni->vr2);
				tekuci = tekuciInterni->l;
			}

			
		}
		else {
			break;
		}
		
	}
}

/*
	Level order obilazak za brisanje stabla
*/
void brisanjeStabla(Cvor* koren) {
	Red red;
	Cvor* tekuci;
	Interni* tekuciInterni;
	Eksterni* tekuciEksterni;

	inicijalizujRed(&red);

	dodajRed(&red, koren);

	while (!redPrazan(&red)) {
		tekuci = uzmiRed(&red);

		if (tekuci->vrsta != E) {
			tekuciInterni = ((Interni*)tekuci->podaci);

			dodajRed(&red, tekuciInterni->l);
			dodajRed(&red, tekuciInterni->d);

			dealocirajInterni(tekuciInterni);
		}
		else {
			tekuciEksterni = ((Eksterni*)tekuci->podaci);

			dealocirajEksterni(tekuciEksterni);
		}

		free(tekuci);
	}
}

/*
	Level order obilazak za izracunavanje interne duzine puta. U red se nikad ne dodaju eksterni cvorovi jer njihova vrednost nivoa ne utice na internu duzinu
*/
int internaDuzinaPuta(Cvor* koren) {
	Red red;
	Cvor* tekuci;
	Interni* tekuciInterni;
	int duzina = 0;

	inicijalizujRed(&red);

	dodajRed(&red, koren);

	while (!redPrazan(&red)) {
		tekuci = uzmiRed(&red);
		tekuciInterni = ((Interni*)tekuci->podaci);

		duzina += tekuci->nivo;

		if (tekuciInterni->l->vrsta != E) {
			dodajRed(&red, tekuciInterni->l);
		}

		if (tekuciInterni->d->vrsta != E) {
			dodajRed(&red, tekuciInterni->d);
		}
	
	}

	return duzina;
}

/*
	Ispis svih kombinacija za odredjenu rundu vrsi se Postorder obilaskom za koji je potreban stek.
	Ideja je da se za sve interne cvorove odredjene runde, pokupe vrednosti svih eksternih cvorova sa njihove leve i desne strane, a zatim ispisu sve moguce kombinacije parova levog i desnog niza eksternih cvorova.
	U nizovima Osoba** levo i Osoba** desno pamtimo pokazivace na osobe sa leve strane odredjenog cvora i sa njegove desne strane. Promenljive brl i brd u sebi skladiste broj osoba u levom i desnom nizu, jer ce niz imati alocirano vise elemenata nego sto je potrebno. Oba niza ce imati po n elemenata.
*/
void ispisKombinacija(Cvor* koren, int n) {
	Stek stek;
	Cvor* tekuci;
	Interni* tekuciInterni;
	Eksterni* tekuciEksterni;
	int brojNivoa, brojRundi;
	int kraj;
	int runda;
	int nivoRunda;
	Osoba ** levo, ** desno;
	int brl, brd;
	int flagLevo;
	int i, j;
	int brojMeca;

	system("cls");

	brojNivoa = ceil(log2(n)) + 1;

	brojRundi = brojNivoa - 1;

	do {
		kraj = 1;
		printf("Unesite redni broj runde (od %d do %d): ", 1, brojRundi);
		scanf("%d", &runda);

		if (runda < 1 || runda > brojRundi) {
			printf("Morate uneti ispravan broj runde. Ponovite unos.\n");
			kraj = 0;
		}
	} while (!kraj);

	// Runde se racunaju od dole na gore, a nivoi obrnuto
	nivoRunda = brojNivoa - runda - 1;

	inicijalizujStek(&stek);

	levo = (Osoba**)calloc(n, sizeof(Osoba*));

	if (levo == NULL) {
		greskaAlokacijaProstora();
	}

	desno = (Osoba**)calloc(n, sizeof(Osoba*));

	if (desno == NULL) {
		greskaAlokacijaProstora();
	}

	tekuci = koren;

	brojMeca = 1;

	// Postorder obilazak
	while (tekuci != NULL) {
		// Kada naidjemo na cvor iz runde za koju trazimo podatke, resetujemo broj levih i desnih eksternih cvorova, i postavljamo flagLevo na 1, jer prvo obilazimo levo podstablo, pa kad naidjemo na eksterni cvor da znamo da li da osobu dodamo u levi ili desni niz. U levi dodajemo kada je flagLevo = 1 u desni kada je 0
		if (tekuci->nivo == nivoRunda) {
			brl = 0;
			brd = 0;
			flagLevo = 1;
		}

		dodajStek(&stek, tekuci);

		if (tekuci->vrsta == I) {
			tekuciInterni = ((Interni*)tekuci->podaci);
			tekuci = tekuciInterni->l;
		}
		else {
			tekuci = NULL;
		}
	}

	while (!stekPrazan(&stek)) {
		tekuci = uzmiStek(&stek);

		// Vrednost promenljive tekuci->nivo cemo koristiti kao znak da li smo cvoru obisli i levo i desno podstablo, ukoliko je pozitivna vrednost nivoa znaci da smo obisli samo levo podstablo, i zbog toga ga opet vracamo na stek
		if (tekuci->nivo >= 0) {
			// Ukoliko je interni cvor iz runde koju trazimo, krecemo u obilazak desnog podstabla, zato flagLevo = 0
			if (tekuci->nivo == nivoRunda) {
				flagLevo = 0;
			}
			
			// Unutar cvora dajemo signal da smo krenuli u desnu stranu, tako sto stavljamo negativnu vrednost nivoa, ali posto je koren na nivou 0, ne moze se razlikovati -0 i +0, zbog toga umanjujemo negativnu vrednost za 1
			tekuci->nivo = -tekuci->nivo - 1;

			dodajStek(&stek, tekuci);

			if (tekuci->vrsta == I) {
				tekuciInterni = ((Interni*)tekuci->podaci);
				tekuci = tekuciInterni->d;
			}else{
				tekuci = NULL;
			}

			while (tekuci != NULL) {
				if (tekuci->nivo == nivoRunda) {
					brl = 0;
					brd = 0;
					flagLevo = 1;
				}

				dodajStek(&stek, tekuci);

				if (tekuci->vrsta == I) {
					tekuciInterni = ((Interni*)tekuci->podaci);
					tekuci = tekuciInterni->l;
				}
				else {
					tekuci = NULL;
				}
			}
		}
		else {
			// Vracamo prvobitnu vrednost nivou
			tekuci->nivo = -tekuci->nivo -1;

			// Ako je cvor interni i na nivou runde koju trazimo, treba da ispisemo sve kombinacije iz niza levo i desno
			if (tekuci->vrsta == I && tekuci->nivo == nivoRunda) {
				printf("Mec %d - potencijalni parovi\n=========================================\n", brojMeca);
				brojMeca++;

				for (i = 0; i < brl; i++) {
					for (j = 0; j < brd; j++) {
						printf("(%d) %s vs. (%d) %s\n", levo[i]->nosilac, levo[i]->ime, desno[j]->nosilac, desno[j]->ime);
					}
					printf("\n");
				}
			}
			// Ako je cvor eksterni dodajemo ga u niz levo ili desno u zavisnosti od flagLevo
			else if(tekuci->vrsta == E){
				tekuciEksterni = ((Eksterni*)tekuci->podaci);

				if (flagLevo) {
					levo[brl++] = tekuciEksterni->osoba;
				}
				else {
					desno[brd++] = tekuciEksterni->osoba;
				}
			}
		}


	}
	
	// Oslobadjamo prostor koji nam je bio potreban za implementaciju ove funkcije
	free(levo);
	free(desno);
}

void main() {
	// Odabirom opcije 0 iz menija program se zavrsava i kraj dobija vrednost 1, program se radi u do-while petlji sve dok je vrednost promenljive kraj 0
	int kraj = 0;
	// Izabrana opcija iz menija
	int opcija;
	// Ukoliko se izabere neka opcija iz menija koja nije ponudjena, korektanUnos promenljiva ce imati vrednost 0 i meni ce se ponovo ispisati sve dok korisnik korektno ne odabere opciju
	int korektanUnos;
	// Promenljive formiranoStablo i unetiRezultati su logickog tipa i sluze da se zabrane ostale akcije dok ove dve promenljive nemaju vrednost 1, tj. dok se ne formira stablo i unesu rezultati (opcije 1 i 2)
	int formiranoStablo = 0, unetiRezultati = 0;
	// Broj ucesnika turnira
	int n = 0;
	// Promenljiva za internu duzinu puta
	int interna;
	// Koren stabla
	Cvor* koren = NULL;

	do {
		// brisanje konzole
		system("cls");

		printf("==============================MENI=============================\n\n");

		printf("1) Formiranje stabla\n");
		printf("2) Unos rezultata na turniru\n");
		printf("3) Ispis pobednika turnira\n");
		printf("4) Ispisivanje svih mogucih parova igraca u rundi\n");
		printf("5) Ispis stabla\n");
		printf("6) Brisanje stabla\n\n");
		printf("7) Odredjivanje interne duzine puta u stablu\n\n");
		printf("0) Prekid programa\n");

		do {
			korektanUnos = 1;

			printf("\nUnesite opciju: ");
			scanf("%d", &opcija);

			switch (opcija) {
			case 0:
				kraj = 1;
				break;
			case 1:
				// ako je stablo vec formirano potrebno ga je obrisati pre ponovnog formiranja
				if (formiranoStablo) {
					brisanjeStabla(koren);
					koren = NULL;
					formiranoStablo = 0;
					unetiRezultati = 0;
				}

				koren = formirajStablo(&n);
				formiranoStablo = 1;
				break;
			case 2:
				if (formiranoStablo) {
					unosRezultataTurnira(koren);
					unetiRezultati = 1;
				}
				else {
					printf("Morate formirati stablo pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			case 3:
				// informacija o pobedniku turnira se nalazi u korenu stabla
				if (formiranoStablo && unetiRezultati) {
					system("cls");
					printf("Pobednik turnira je: (%d) %s", ((Interni*)koren->podaci)->pobednik->nosilac, ((Interni*)koren->podaci)->pobednik->ime);
					_sleep(4000);
				}
				else {
					printf("Morate formirati stablo i uneti rezultate turnira pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			case 4:
				if (formiranoStablo) {
					ispisKombinacija(koren, n);
					_sleep(10000);
				}
				else {
					printf("Morate formirati stablo pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			case 5:
				if (formiranoStablo) {
					ispisStabla(koren);
					_sleep(10000);
				}
				else {
					printf("Morate formirati stablo pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			case 6:
				if (formiranoStablo) {
					brisanjeStabla(koren);
					koren = NULL;
					formiranoStablo = 0;
					unetiRezultati = 0;
				}
				else {
					printf("Morate formirati stablo pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			case 7:
				if (formiranoStablo) {
					interna = internaDuzinaPuta(koren);
					system("cls");
					printf("Interna duzina puta iznosi: %d\n", interna);
					_sleep(4000);
				}
				else {
					printf("Morate formirati stablo pre koriscenja ove funkcije!\n");
					_sleep(2000);
				}
				break;
			default:
				korektanUnos = 0;
				break;
			}
		} while (!korektanUnos);

	} while (!kraj);

	if (formiranoStablo) {
		brisanjeStabla(koren);
	}
}