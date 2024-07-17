import re
from collections import OrderedDict

def build_test_data(raw_text):
    words_list = raw_text.split()
    pnum_map = OrderedDict()
    word_index_map = OrderedDict()
    par_num = -1
    cursor = 0
    for index, word in enumerate(words_list):
        if re.match(r'\d+', word):
            par_num = int(word)
            pnum_map[par_num] = index
        pos = raw_text[cursor:].index(word)
        word_index_map[index] = pos + cursor
        cursor += pos + len(word)

    pnum_map[par_num+1] = len(words_list)
    word_index_map[len(words_list)] = len(raw_text)

    return {
        'raw_text': raw_text,
        'words_list': words_list,
        'pnum_map': pnum_map,
        'word_index_map': word_index_map
    }

SIMPLE_TEST = {
    'quote': 'quote test',
    'english_data': build_test_data('1 this is a simple quote test 2 end'),
    'spanish_data': build_test_data('1 esta es una prueba de cotización simple 2 fin'),
    'expected': {
        'quote': 'quote test ', 
        'translation': 'una prueba de cotización simple ', 
        'paragraphNumber': 1
    }
}

FULL_PARAGRAPH = {
    'quote': 'God loves to fellowship with His creature. In the garden of Eden we are told, that when man walked in the uprightness of God, God came down in the cool of the evening and fellowshipped with His children. Then, one day there was a voice came up in the Presence of God and said, “Those Your loved ones, Your children, has fallen, and they have sinned and have did that which was wrong.” You know what…?…God didn’t just select some Angel to go down and look it over, to see if it was so or not, or a certain Cherubim of the heavens, but God came Hisself, crying, “Adam, where art Thou?” God, Himself, come crying for His lost child. When He found Him hiding in the bushes, behind sewed fig leaves, He said, “Who told you you were naked?” And he could not come out and have fellowship no more with God.',
    'english_data': build_test_data('[Blank.spot.on.tape] Man...\n9 God loves to fellowship with His creature. In the garden of Eden we are told, that when man walked in the uprightness of God, God came down in the cool of the evening and fellowshipped with His children. Then, one day there was a voice came up in the Presence of God and said, “Those Your loved ones, Your children, has fallen, and they have sinned and have did that which was wrong.” You know what...?... God didn\'t just select some Angel to go down and look it over, to see if it was so or not, or a certain Cherubim of the heavens, but God came Hisself, crying, “Adam, where art Thou?” God, Himself, come crying for His lost child.\nWhen He found Him hiding in the bushes, behind sewed fig leaves, He said, “Who told you you were naked?” And he could not come out and have fellowship no more with God. 10 Now, if there is a true fellowship... And God is love, and love demands a fellowship, like the young couple. When the boy meets the girl, and he says to her... He thinks she\'s so pretty, and—and she\'s fond of him, they want to have fellowship, a real fellowship. But before they can have this fellowship, there has to be an agreement. Before they can enter into wedding, wedlock, there has to an agreement for this certain fellowship. And it\'s based upon the truces or their pledges to each other, and then holy wedlock. And then we enter into a life-long fellowship. But before we can enter into that fellowship, there has to be a—an agreement first.'),
    'spanish_data': build_test_data('[Porción sin grabar en la cinta-Ed.].\n9 Dios ama tener compañerismo con Sus criaturas. En el huerto del Edén, se nos dijo, que cuando el hombre caminaba en la rectitud de Dios, Dios descendía en la frescura de la tarde y tenía compañerismo con Sus hijos. Luego, un día hubo una voz que subió a la Presencia de Dios, y dijo: “Esos, Tus amados, Tus hijos, han caído, y han pecado y han hecho eso, lo cual está errado”. Saben qué?, Dios no seleccionó a algún Angel para que bajara e investigara, para ver si era así o no, o a un cierto Querubín de los Cielos, sino que Dios mismo vino, clamando: “Adán, dónde estás?” Dios mismo vino clamando por Su hijo perdido.\nCuando El lo encontró escondido en los arbustos, detrás de las hojas de higuera cosidas, El dijo: “Quién te enseñó que estabas desnudo?” Y él ya no pudo salir y tener compañerismo con Dios. 10 Ahora, si hay un compañerismo verdadero... Y Dios es amor, y el amor demanda un compañerismo. Así como una pareja joven: cuando el muchacho conoce a la muchacha, y él le dice a ella... él piensa que ella es muy hermosa, y-y ella está enamorada de él; ellos quieren tener compañerismo, un verdadero compañerismo. Pero antes que ellos puedan tener este compañerismo, tiene que haber un acuerdo. Antes que puedan entrar en la boda, en matrimonio, tiene que haber un acuerdo para este cierto compañerismo. Y es basado sobre la seguridad de sus promesas hechas el uno al otro, y luego el matrimonio. Y luego entramos en un compañerismo por toda la vida. Pero antes que podamos entrar en ese compañerismo, primero tiene que haber un-un acuerdo.'),
    'expected': {
        'quote': 'God loves to fellowship with His creature. In the garden of Eden we are told, that when man walked in the uprightness of God, God came down in the cool of the evening and fellowshipped with His children. Then, one day there was a voice came up in the Presence of God and said, “Those Your loved ones, Your children, has fallen, and they have sinned and have did that which was wrong.” You know what...?... God didn\'t just select some Angel to go down and look it over, to see if it was so or not, or a certain Cherubim of the heavens, but God came Hisself, crying, “Adam, where art Thou?” God, Himself, come crying for His lost child.\nWhen He found Him hiding in the bushes, behind sewed fig leaves, He said, “Who told you you were naked?” And he could not come out and have fellowship no more with God. ', 
        'translation': 'Dios ama tener compañerismo con Sus criaturas. En el huerto del Edén, se nos dijo, que cuando el hombre caminaba en la rectitud de Dios, Dios descendía en la frescura de la tarde y tenía compañerismo con Sus hijos. Luego, un día hubo una voz que subió a la Presencia de Dios, y dijo: “Esos, Tus amados, Tus hijos, han caído, y han pecado y han hecho eso, lo cual está errado”. Saben qué?, Dios no seleccionó a algún Angel para que bajara e investigara, para ver si era así o no, o a un cierto Querubín de los Cielos, sino que Dios mismo vino, clamando: “Adán, dónde estás?” Dios mismo vino clamando por Su hijo perdido.\nCuando El lo encontró escondido en los arbustos, detrás de las hojas de higuera cosidas, El dijo: “Quién te enseñó que estabas desnudo?” Y él ya no pudo salir y tener compañerismo con Dios. ', 
        'paragraphNumber': 9
    }
}

