package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthStorage struct {
	connection      *gorm.DB
	shards          []*gorm.DB
	shardWriteQueue chan User
}

func InitDB() *AuthStorage {
	var err error

	// Load .env file

	dbUrl := os.Getenv("DB_URL")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	prodDbUrl := os.Getenv("DATABASE_URL")
	// prodShard1Url := os.Getenv("POSTGRES_PROD_SHARD_1_URL")
	// prodShard2Url := os.Getenv("POSTGRES_PROD_SHARD_2_URL")

	var DBConn *gorm.DB
	var shardDBs []*gorm.DB

	if prodDbUrl != "" {
		fmt.Printf("Connecting to database %s", prodDbUrl)
		DBConn, err = gorm.Open(postgres.Open(prodDbUrl), &gorm.Config{TranslateError: true})

		// shardDBs = []*gorm.DB{
		// 	initShardDB(prodShard1Url),
		// 	initShardDB(prodShard2Url),
		// 	// Add more shards here
		// }
	} else {
		connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbUser, dbPassword, dbUrl, dbName)
		fmt.Printf("Connecting to database postgres://%s:%s@%s/%s?sslmode=disable", dbUser, dbPassword, dbUrl, dbName)

		DBConn, err = gorm.Open(postgres.Open(connStr), &gorm.Config{TranslateError: true})

		// shardDBs = []*gorm.DB{
		// 	initShardDB(fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbUser, dbPassword, dbUrl, "shard1")),
		// 	initShardDB(fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbUser, dbPassword, dbUrl, "shard2")),
		// 	// Add more shards here
		// }
	}

	shardWriteQueue := make(chan User, 100)
	// go shardWorker(shardWriteQueue, shardDBs)

	if err != nil {
		panic("Failed to connect to database!")
	}

	err = DBConn.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error

	if err != nil {
		panic("Failed to create extension!")
	}

	err = DBConn.AutoMigrate(&User{}, &RefreshToken{})

	if err != nil {
		fmt.Println("Failed to migrate database!")
		panic(err)
	}
	// for _, shard := range shardDBs {
	// 	err = shard.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error
	// 	if err != nil {
	// 		panic("Failed to create extension!")
	// 	}
	// 	err = shard.AutoMigrate(&User{}, &RefreshToken{})
	// 	if err != nil {
	// 		fmt.Println("Failed to migrate shard database!")
	// 		panic(err)
	// 	}
	// }

	return &AuthStorage{
		connection:      DBConn,
		shards:          shardDBs,
		shardWriteQueue: shardWriteQueue,
	}
}

// Determine shard by using hash of UserId
func determineShardByUserID(userID string, shardCount uint32) int {
	uuid, err := uuid.Parse(userID)
	if err != nil {
		fmt.Println("Failed to parse UUID", userID)
	}
	hash := sha256.Sum256(uuid[:])

	shardID := binary.BigEndian.Uint32(hash[:4]) % shardCount
	return int(shardID)
}

// Queue a task for writing to the shard
func QueueShardWrite(user User, shardWriteQueue chan User) {
	select {
	case shardWriteQueue <- user: // Enqueue the user to the shard write queue
		fmt.Printf("User with ID %s enqueued for shard write\n", user.UserId)
	default:
		fmt.Println("Shard write queue is full. Task could not be enqueued.")
	}
}

// Background worker that processes shard write tasks asynchronously
func shardWorker(shardWriteQueue chan User, shards []*gorm.DB) {
	for user := range shardWriteQueue {
		WriteToShard(user, shards)
	}
}

// Write user to the appropriate shard
func WriteToShard(user User, shards []*gorm.DB) {
	shardID := determineShardByUserID(user.UserId, uint32(len(shards)))
	shardDB := shards[shardID]
	// Write user data to the selected shard
	if err := shardDB.Clauses(clause.OnConflict{DoNothing: true}).Save(&user).Error; err != nil {
		log.Printf("Failed to write to shard DB %d: %v", shardID, err)
	} else {
		// @TODO Add exact shard name
		fmt.Printf("User with ID %s written to shard of index %d with name \n", user.UserId, shardID)
	}
}

// Read from the appropriate shard based on UserId
func ReadFromShard(userID string, shards []*gorm.DB) (User, error) {
	shardID := determineShardByUserID(userID, uint32(len(shards)))
	shardDB := shards[shardID]

	var user User
	err := shardDB.Model(&User{}).Where("user_id = ?", userID).First(&user).Error
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func initShardDB(dsn string) *gorm.DB {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		log.Fatalf("Failed to connect to shard DB: %v", err)
	}
	return db
}

func (authStore *AuthStorage) CreateTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		user_id SERIAL PRIMARY KEY,
		first_name TEXT NOT NULL,
		last_name TEXT NOT NULL,
		password TEXT NOT NULL,
		is_admin BOOLEAN NOT NULL,
    	updated_at TIMESTAMPTZ NOT NULL,
    	created_at TIMESTAMPTZ NOT NULL,
		email TEXT NOT NULL UNIQUE
	)`

	if err := authStore.connection.Exec(query).Error; err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users Table created successfully!")
}

func (authStore *AuthStorage) CreateJTITable() {
	query := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
    	id SERIAL PRIMARY KEY,
    	user_id TEXT NOT NULL,
    	jti UUID NOT NULL,
    	expiry TIMESTAMPTZ NOT NULL,
    	is_revoked BOOLEAN DEFAULT FALSE
	);`

	if err := authStore.connection.Exec(query).Error; err != nil {
		log.Fatal(err)
	}

	fmt.Println("Refresh Tokens Table created successfully!")
}

func (authStore *AuthStorage) GetDB() *gorm.DB {
	return authStore.connection
}
