package utils

import (
	"encoding/json"
	"log"
	"net/http"

	"auth-microservice/internal/models"
)

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}

// WriteError writes a JSON error response
func WriteError(w http.ResponseWriter, status int, err string, message string) {
	response := models.ErrorResponse{
		Error:   err,
		Message: message,
	}
	WriteJSON(w, status, response)
}

// ParseJSON parses JSON request body
func ParseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
