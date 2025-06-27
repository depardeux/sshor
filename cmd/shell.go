/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/hurlebouc/sshor/config"
	"github.com/hurlebouc/sshor/ssh"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

// shellCmd represents the shell command
var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Open a remote shell in SSH",
	Long:  `Open a remote shell in SSH`,
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return findAllPossibleHosts(toComplete), cobra.ShellCompDirectiveDefault
		} else {
			return []string{}, cobra.ShellCompDirectiveDefault
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		ssh.Shell(getHostConfig(readConf(), args[0]), passwordFlag, keepassPwdFlag)
	},
}

var manageCmd = &cobra.Command{
	Use:   "manage",
	Short: "Gérer le salt et les fichiers cache Keepass",
}

var manageSaltCmd = &cobra.Command{
	Use:   "salt",
	Short: "Générer un salt (Base64, 32 octets) et l'enregistrer dans %APPDATA%",
	Run: func(cmd *cobra.Command, args []string) {
		bytes := make([]byte, 32)
		_, err := rand.Read(bytes)
		if err != nil {
			panic("Erreur lors de la génération du salt : " + err.Error())
		}
		base64Salt := base64.StdEncoding.EncodeToString(bytes)
		configDir, err := os.UserConfigDir()
		if err != nil {
			panic("Erreur lors de la récupération du dossier de configuration utilisateur : " + err.Error())
		}
		filePath := filepath.Join(configDir, "sshor_keepass_salt.txt")
		err = os.WriteFile(filePath, []byte(base64Salt), 0600)
		if err != nil {
			panic("Erreur lors de l'écriture du salt : " + err.Error())
		}
		fmt.Printf("Chaîne Base64 enregistrée dans : %s\n", filePath)
	},
}

var manageCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Supprimer les fichiers sshor_keepass_* dans le dossier Temp",
	Run: func(cmd *cobra.Command, args []string) {
		tempDir := os.TempDir()
		files, err := filepath.Glob(filepath.Join(tempDir, "sshor_keepass_*"))
		if err != nil {
			panic("Erreur lors de la recherche des fichiers : " + err.Error())
		}
		if len(files) == 0 {
			fmt.Printf("Aucun fichier correspondant trouvé dans %s\n", tempDir)
			return
		}
		for _, file := range files {
			err := os.Remove(file)
			if err != nil {
				fmt.Printf("Erreur lors de la suppression de %s : %v\n", file, err)
			} else {
				fmt.Printf("Fichier supprimé : %s\n", filepath.Base(file))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(manageCmd)
	manageCmd.AddCommand(manageSaltCmd)
	manageCmd.AddCommand(manageCleanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// shellCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// shellCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func findAllPossibleHosts(toComplete string) []string {
	login, host, _ := splitFullHost(toComplete)

	config, err := config.ReadConf()
	if err != nil {
		panic(err)
	}
	if config == nil {
		return []string{}
	}

	keys := make([]string, 0, len(config.Hosts))
	for k := range config.Hosts {
		keys = append(keys, k)
	}

	return lo.Map(lo.Filter(keys, func(item string, idx int) bool { return strings.HasPrefix(item, host) }), func(item string, idx int) string {
		if login == nil {
			return item
		} else {
			return *login + "@" + item
		}
	})
}
