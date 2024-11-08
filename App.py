from PIL import Image, ImageTk
import tkinter as tk

class BlockchainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aether AI - Blockchain Explorer")
        
        # Carregar a imagem do logo
        self.logo = Image.open(r"C:\Users\Igor Silva\Cripto_Moeda\Criptomoeda.png")
        self.logo = self.logo.resize((500, 500), Image.LANCZOS)
        self.logo = ImageTk.PhotoImage(self.logo)
        
        # Exibir o logo
        self.logo_label = tk.Label(root, image=self.logo)
        self.logo_label.pack(pady=10)

# Configurar a janela principal do Tkinter
root = tk.Tk()
app = BlockchainApp(root)
root.mainloop()
